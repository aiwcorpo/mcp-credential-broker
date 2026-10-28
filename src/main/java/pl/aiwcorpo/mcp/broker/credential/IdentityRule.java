package pl.aiwcorpo.mcp.broker.credential;

import java.text.Normalizer;
import java.util.Map;

import pl.aiwcorpo.mcp.broker.system.BackendIdentity;

/**
 * C4.1: the account in the target system must be the SSO user's own. When both raw values are pure ASCII the
 * comparison ignores ASCII letter case; otherwise it is exact equality after Unicode NFC, with no case
 * folding (a Unicode lower-casing would equate U+212A KELVIN SIGN with "k" and U+0130 with "i"). No trimming,
 * substring, prefix or domain stripping, and an empty value never matches. The e-mail counts only when the IdP sets {@code email_verified} to true, because in
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
        if (isAscii(sso) && isAscii(system)) {
            return sso.equalsIgnoreCase(system);
        }
        return Normalizer.normalize(sso, Normalizer.Form.NFC).equals(Normalizer.normalize(system, Normalizer.Form.NFC));
    }

    private static boolean isAscii(String value) {
        return value.chars().allMatch(c -> c < 0x80);
    }
}
