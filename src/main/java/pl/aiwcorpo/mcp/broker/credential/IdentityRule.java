package pl.aiwcorpo.mcp.broker.credential;

import java.text.Normalizer;
import java.util.Locale;
import java.util.Map;

import pl.aiwcorpo.mcp.broker.system.BackendIdentity;

/**
 * C4.1: the account in the target system must be the SSO user's own. Exact equality after Unicode NFC and
 * lower-casing (root locale) of both sides; no trimming, substring, prefix or domain stripping, and an empty
 * value never matches. The e-mail counts only when the IdP sets {@code email_verified} to true, because in
 * some IdPs users change their e-mail themselves. Checked against test-vectors/whoami-identity.
 */
public final class IdentityRule {

    public static final String EMAIL_CLAIM = "email";

    private IdentityRule() {
    }

    public static boolean matches(String ssoClaim, Map<String, Object> ssoClaims, BackendIdentity backend) {
        boolean byEmail = EMAIL_CLAIM.equals(ssoClaim);
        if (byEmail && !Boolean.TRUE.equals(ssoClaims.get("email_verified"))) {
            return false;
        }
        Object expected = ssoClaims.get(ssoClaim);
        String actual = byEmail ? backend.email() : backend.username();
        return expected instanceof String sso && sameIdentity(sso, actual);
    }

    static boolean sameIdentity(String sso, String system) {
        if (sso == null || system == null || sso.isEmpty() || system.isEmpty()) {
            return false;
        }
        return fold(sso).equals(fold(system));
    }

    private static String fold(String value) {
        String composed = Normalizer.normalize(value, Normalizer.Form.NFC);
        return Normalizer.normalize(composed.toLowerCase(Locale.ROOT), Normalizer.Form.NFC);
    }
}
