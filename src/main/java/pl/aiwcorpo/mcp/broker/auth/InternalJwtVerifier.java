package pl.aiwcorpo.mcp.broker.auth;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
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
    private static final Set<String> USER_REQUIRED = union(COMMON_CLAIMS, Set.of("usr", "azp"));
    private static final Set<String> USER_ALLOWED = union(USER_REQUIRED, Set.of("tool", "vs", "vsc", "mfa"));

    /** vsc fields and the id pattern of each (common.schema.json, CC-056); at most 50 ids per field. */
    private static final Map<String, Pattern> VSC_ID_PATTERNS = Map.of(
            "jiraProjects", Pattern.compile("^[A-Z][A-Z0-9_]{1,9}$"),
            "confluenceSpaces", Pattern.compile("^[A-Za-z0-9]{1,255}$"),
            "gitlabGroups", Pattern.compile(
                    "^(?!.*\\.(?:git|atom)$)[A-Za-z0-9](?:[._-]?[A-Za-z0-9])*(?:/[A-Za-z0-9](?:[._-]?[A-Za-z0-9])*){0,19}$"),
            "opensearchIndexPrefixes", Pattern.compile("^(?!\\.{1,2}$)[a-z0-9.][a-z0-9._-]{0,253}[a-z0-9_]$|^[a-z0-9]$"),
            "servicedeskQueues", Pattern.compile("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"));
    private static final int VSC_MAX_IDS = 50;
    private static final int GITLAB_PATH_MAX_LENGTH = 1024;

    /**
     * SHA-256 of the SPKI of every EC key published in mcp-contracts test-vectors/keys (gateway A and B,
     * attacker, test IdP). A published key is refused whatever kid it is served under (CC-044).
     */
    static final Set<String> TEST_KEY_SPKI_SHA256 = Set.of(
            "2c9b2f1e8cc291d8f9ab8a2c312726a1d9162253038d3670363084d5e2a07147",
            "f776f49706b7fa2a9368b66d075bbb8ae737911125f4f144187b9a586f31eccc",
            "c679efaec91adf76e792b3d56d1d59d5da3a3a6c4378da690c9c00f6ceff010a",
            "8a264c8d907f48620d4f5963d2e5250766b5845cd5263677554575041e86de2f");

    /** Rule for the {@code tool} claim of the user variant (CC-038). */
    public enum ToolClaim {
        /** tools/call and the broker's resolve: the call is for one tool. */
        REQUIRED,
        /** Protocol methods and GET /v1/systems: no tool is being called. */
        FORBIDDEN
    }

    private final String issuer;
    private final String audience;
    private final GatewayKeys keys;
    private final ReplayGuard replayGuard;
    private final Clock clock;
    private final long skewSeconds;
    private final long maxLifetimeSeconds;
    private final boolean allowTestKeys;
    private final boolean devMode;

    public InternalJwtVerifier(String issuer, String audience, GatewayKeys keys, ReplayGuard replayGuard, Clock clock,
            Duration clockSkew, Duration maxLifetime, boolean allowTestKeys) {
        this(issuer, audience, keys, replayGuard, clock, clockSkew, maxLifetime, allowTestKeys, false);
    }

    /**
     * @param devstackProfile the devstack profile is active; keys whose kid starts with {@code dev-} are accepted only
     *                        together with {@code allowTestKeys} (CC-137), which is what dev mode means
     */
    public InternalJwtVerifier(String issuer, String audience, GatewayKeys keys, ReplayGuard replayGuard, Clock clock,
            Duration clockSkew, Duration maxLifetime, boolean allowTestKeys, boolean devstackProfile) {
        this.issuer = issuer;
        this.audience = audience;
        this.keys = keys;
        this.replayGuard = replayGuard;
        this.clock = clock;
        this.skewSeconds = clockSkew.toSeconds();
        this.maxLifetimeSeconds = maxLifetime.toSeconds();
        this.allowTestKeys = allowTestKeys;
        this.devMode = allowTestKeys && devstackProfile;
    }

    /**
     * @param token                 compact JWS from the Authorization header, or null
     * @param xRequestId            value of the X-Request-Id header, or null
     * @param serviceVariantAllowed true only for operations that accept the service variant (GET /v1/systems)
     * @param toolClaim             whether the user variant must or must not carry {@code tool}
     */
    public InternalJwtClaims verify(String token, String xRequestId, boolean serviceVariantAllowed, ToolClaim toolClaim) {
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
        if (!service && toolClaim == ToolClaim.REQUIRED && verified.tool() == null) {
            throw new TokenRejectedException("tool_missing");
        }
        if (!service && toolClaim == ToolClaim.FORBIDDEN && verified.tool() != null) {
            throw new TokenRejectedException("tool_not_allowed");
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
        if ((!allowTestKeys && kid.startsWith("test-")) || (!devMode && kid.startsWith("dev-"))) {
            throw new TokenRejectedException("test_key_not_allowed");
        }
        Optional<ECKey> key = keys.find(kid);
        if (key.isEmpty() || !Curve.P_256.equals(key.get().getCurve())) {
            throw new TokenRejectedException("unknown_kid");
        }
        if (!allowTestKeys && isPublishedTestKey(key.get())) {
            throw new TokenRejectedException("test_key_not_allowed");
        }
        try {
            if (!jwt.verify(new ECDSAVerifier(key.get()))) {
                throw new TokenRejectedException("bad_signature");
            }
        } catch (JOSEException e) {
            throw new TokenRejectedException("bad_signature");
        }
    }

    static boolean isPublishedTestKey(ECKey key) {
        try {
            byte[] spki = key.toECPublicKey().getEncoded();
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(spki));
            return TEST_KEY_SPKI_SHA256.contains(digest);
        } catch (JOSEException | NoSuchAlgorithmException e) {
            return true;
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
        String tool = null;
        if (claims.containsKey("tool")) {
            tool = string(claims, "tool", 64);
            if (!TOOL_NAME.matcher(tool).matches()) {
                throw new TokenRejectedException("invalid_claims");
            }
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
        if (!(value instanceof Map<?, ?> vsc) || !VSC_ID_PATTERNS.keySet().containsAll(vsc.keySet())) {
            throw new TokenRejectedException("invalid_claims");
        }
        for (Map.Entry<?, ?> field : vsc.entrySet()) {
            Pattern pattern = VSC_ID_PATTERNS.get(field.getKey());
            if (!(field.getValue() instanceof List<?> list) || list.isEmpty() || list.size() > VSC_MAX_IDS
                    || new HashSet<>(list).size() != list.size()) {
                throw new TokenRejectedException("invalid_claims");
            }
            for (Object id : list) {
                if (!(id instanceof String s) || s.length() > GITLAB_PATH_MAX_LENGTH || !pattern.matcher(s).matches()) {
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
