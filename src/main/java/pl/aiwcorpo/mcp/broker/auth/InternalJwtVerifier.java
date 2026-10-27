package pl.aiwcorpo.mcp.broker.auth;

import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;

/**
 * Receiver side of the gateway's internal JWT (C2, schemas/internal-jwt.schema.json) for the broker.
 * Checks, in order: ES256 only, kid known (and not a published test kid in production), signature, claim
 * shape of the user or service variant, iss, aud as a single string, exp with clock skew, iat not in the
 * future, lifetime, rid == X-Request-Id, service variant only where the operation allows it, and finally
 * the jti replay window. Every failure is a {@link TokenRejectedException} (HTTP 401), never a fallback.
 */
public class InternalJwtVerifier {

    static final Pattern REQUEST_ID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
    private static final Pattern POLICY_REVISION = Pattern.compile("^[0-9]{14}-[0-9a-f]{7}$");
    private static final Pattern GROUP_NAME = Pattern.compile("^mcp-[A-Za-z0-9][A-Za-z0-9._-]*$");
    private static final Pattern TOOL_NAME = Pattern.compile("^[a-z][a-z0-9]*(_[a-z0-9]+)*$");
    private static final Pattern SLUG = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$");
    private static final Pattern COMPONENT_ID = Pattern.compile("^mcp-[a-z0-9]+(-[a-z0-9]+)*$");

    private static final Set<String> COMMON_CLAIMS = Set.of("iss", "aud", "sub", "grp", "rid", "prv", "iat", "exp", "jti");
    private static final Set<String> USER_REQUIRED = union(COMMON_CLAIMS, Set.of("usr", "azp", "tool"));
    private static final Set<String> USER_ALLOWED = union(USER_REQUIRED, Set.of("vs", "vsc", "mfa"));
    private static final Set<String> VSC_KEYS = Set.of(
            "jiraProjects", "confluenceSpaces", "gitlabGroups", "opensearchIndexPrefixes", "servicedeskQueues");

    private final String issuer;
    private final String audience;
    private final GatewayKeys keys;
    private final ReplayGuard replayGuard;
    private final Clock clock;
    private final long skewSeconds;
    private final long maxLifetimeSeconds;
    private final boolean rejectTestKids;

    public InternalJwtVerifier(String issuer, String audience, GatewayKeys keys, ReplayGuard replayGuard, Clock clock,
            Duration clockSkew, Duration maxLifetime, boolean rejectTestKids) {
        this.issuer = issuer;
        this.audience = audience;
        this.keys = keys;
        this.replayGuard = replayGuard;
        this.clock = clock;
        this.skewSeconds = clockSkew.toSeconds();
        this.maxLifetimeSeconds = maxLifetime.toSeconds();
        this.rejectTestKids = rejectTestKids;
    }

    /**
     * @param token                 compact JWS from the Authorization header, or null
     * @param xRequestId            value of the X-Request-Id header, or null
     * @param serviceVariantAllowed true only for operations that accept the service variant (GET /v1/systems)
     */
    public InternalJwtClaims verify(String token, String xRequestId, boolean serviceVariantAllowed) {
        if (token == null || token.isEmpty()) {
            throw new TokenRejectedException("missing_token");
        }
        SignedJWT jwt;
        Map<String, Object> claims;
        try {
            if (!(JWTParser.parse(token) instanceof SignedJWT signed)) {
                throw new TokenRejectedException("alg_not_allowed");
            }
            jwt = signed;
            claims = jwt.getPayload().toJSONObject();
        } catch (ParseException e) {
            throw new TokenRejectedException("malformed");
        }
        if (claims == null) {
            throw new TokenRejectedException("malformed");
        }
        verifySignature(jwt);

        boolean service = InternalJwtClaims.SERVICE_SUB.equals(claims.get("sub"));
        InternalJwtClaims verified = service ? serviceClaims(claims) : userClaims(claims);

        if (!issuer.equals(claims.get("iss"))) {
            throw new TokenRejectedException("wrong_issuer");
        }
        if (!audience.equals(claims.get("aud"))) {
            throw new TokenRejectedException("wrong_audience");
        }
        long iat = number(claims, "iat");
        long exp = number(claims, "exp");
        long now = clock.instant().getEpochSecond();
        if (now > exp + skewSeconds) {
            throw new TokenRejectedException("expired");
        }
        if (iat > now + skewSeconds) {
            throw new TokenRejectedException("not_yet_valid");
        }
        if (exp <= iat || exp - iat > maxLifetimeSeconds) {
            throw new TokenRejectedException("lifetime_too_long");
        }
        if (xRequestId == null || !xRequestId.equals(verified.rid())) {
            throw new TokenRejectedException("request_id_mismatch");
        }
        if (service && !serviceVariantAllowed) {
            throw new TokenRejectedException("service_token_not_allowed");
        }
        Duration window = Duration.ofSeconds(Math.max(1, exp + skewSeconds - now));
        if (!replayGuard.firstUse(verified.jti(), window)) {
            throw new TokenRejectedException("replayed_jti");
        }
        return verified;
    }

    private void verifySignature(SignedJWT jwt) {
        JWSHeader header = jwt.getHeader();
        if (!JWSAlgorithm.ES256.equals(header.getAlgorithm())) {
            throw new TokenRejectedException("alg_not_allowed");
        }
        String kid = header.getKeyID();
        if (kid == null || kid.isEmpty()) {
            throw new TokenRejectedException("unknown_kid");
        }
        if (rejectTestKids && kid.startsWith("test-")) {
            throw new TokenRejectedException("test_kid_not_allowed");
        }
        Optional<ECKey> key = keys.find(kid);
        if (key.isEmpty() || !Curve.P_256.equals(key.get().getCurve())) {
            throw new TokenRejectedException("unknown_kid");
        }
        try {
            if (!jwt.verify(new ECDSAVerifier(key.get()))) {
                throw new TokenRejectedException("bad_signature");
            }
        } catch (JOSEException e) {
            throw new TokenRejectedException("bad_signature");
        }
    }

    private InternalJwtClaims serviceClaims(Map<String, Object> claims) {
        if (!claims.keySet().equals(COMMON_CLAIMS)) {
            throw new TokenRejectedException("invalid_claims");
        }
        if (!(claims.get("grp") instanceof List<?> grp) || !grp.isEmpty()) {
            throw new TokenRejectedException("invalid_claims");
        }
        commonShape(claims);
        return new InternalJwtClaims(InternalJwtClaims.SERVICE_SUB, null, List.of(), null, null, null,
                (String) claims.get("rid"), (String) claims.get("prv"), (String) claims.get("jti"), true);
    }

    private InternalJwtClaims userClaims(Map<String, Object> claims) {
        if (!claims.keySet().containsAll(USER_REQUIRED) || !USER_ALLOWED.containsAll(claims.keySet())) {
            throw new TokenRejectedException("invalid_claims");
        }
        commonShape(claims);
        String sub = string(claims, "sub", 255);
        if (sub.startsWith("system:")) {
            throw new TokenRejectedException("invalid_claims");
        }
        String usr = string(claims, "usr", 255);
        String azp = string(claims, "azp", 255);
        String tool = string(claims, "tool", 64);
        if (!TOOL_NAME.matcher(tool).matches()) {
            throw new TokenRejectedException("invalid_claims");
        }
        List<String> grp = groups(claims.get("grp"));
        boolean hasVs = claims.containsKey("vs");
        if (hasVs != claims.containsKey("vsc")) {
            throw new TokenRejectedException("invalid_claims");
        }
        String vs = null;
        if (hasVs) {
            vs = string(claims, "vs", 63);
            if (!SLUG.matcher(vs).matches()) {
                throw new TokenRejectedException("invalid_claims");
            }
            virtualServerScopes(claims.get("vsc"));
        }
        if (claims.containsKey("mfa") && (!(claims.get("mfa") instanceof Number mfa) || mfa.longValue() < 0
                || mfa.doubleValue() != mfa.longValue())) {
            throw new TokenRejectedException("invalid_claims");
        }
        return new InternalJwtClaims(sub, usr, grp, azp, tool, vs,
                (String) claims.get("rid"), (String) claims.get("prv"), (String) claims.get("jti"), false);
    }

    private static void commonShape(Map<String, Object> claims) {
        string(claims, "iss", 2048);
        if (!(claims.get("aud") instanceof String aud) || !COMPONENT_ID.matcher(aud).matches() || aud.length() > 64) {
            throw new TokenRejectedException("invalid_claims");
        }
        if (!REQUEST_ID.matcher(string(claims, "rid", 36)).matches()
                || !POLICY_REVISION.matcher(string(claims, "prv", 22)).matches()) {
            throw new TokenRejectedException("invalid_claims");
        }
        string(claims, "jti", 128);
        number(claims, "iat");
        number(claims, "exp");
    }

    private static List<String> groups(Object value) {
        if (!(value instanceof List<?> list)) {
            throw new TokenRejectedException("invalid_claims");
        }
        List<String> groups = new ArrayList<>(list.size());
        for (Object item : list) {
            if (!(item instanceof String group) || group.length() > 255 || !GROUP_NAME.matcher(group).matches()) {
                throw new TokenRejectedException("invalid_claims");
            }
            groups.add(group);
        }
        if (new HashSet<>(groups).size() != groups.size()) {
            throw new TokenRejectedException("invalid_claims");
        }
        return List.copyOf(groups);
    }

    private static void virtualServerScopes(Object value) {
        if (!(value instanceof Map<?, ?> vsc) || !VSC_KEYS.containsAll(vsc.keySet())) {
            throw new TokenRejectedException("invalid_claims");
        }
        for (Object ids : vsc.values()) {
            if (!(ids instanceof List<?> list) || list.isEmpty() || new HashSet<>(list).size() != list.size()) {
                throw new TokenRejectedException("invalid_claims");
            }
            for (Object id : list) {
                if (!(id instanceof String s) || s.isEmpty()) {
                    throw new TokenRejectedException("invalid_claims");
                }
            }
        }
    }

    private static String string(Map<String, Object> claims, String name, int maxLength) {
        if (!(claims.get(name) instanceof String value) || value.isEmpty() || value.length() > maxLength) {
            throw new TokenRejectedException("invalid_claims");
        }
        return value;
    }

    private static long number(Map<String, Object> claims, String name) {
        if (!(claims.get(name) instanceof Number value) || value.doubleValue() != value.longValue() || value.longValue() < 0) {
            throw new TokenRejectedException("invalid_claims");
        }
        return value.longValue();
    }

    private static Set<String> union(Set<String> a, Set<String> b) {
        Set<String> union = new HashSet<>(a);
        union.addAll(b);
        return Set.copyOf(union);
    }
}
