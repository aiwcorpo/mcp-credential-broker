package pl.aiwcorpo.mcp.broker.api;

import java.util.regex.Pattern;

/**
 * {@code returnPath} of C4 oauth/start (CC-032, CC-099): a portal path with an optional query, without percent
 * encoding, backslash or semicolon, so no decoding pass can turn it into //host. It also must not name a prefix the
 * reverse proxy sends to the BFF or the gateway (/api, /s, /v, /.well-known as whole segments) and must not hold a
 * "." or ".." segment before the query, which a browser would resolve to such a prefix.
 */
public final class ReturnPath {

    private static final Pattern PATTERN = Pattern.compile(
            "^(?![^?]*/\\.\\.?(?:[/?]|$))(?!/(?:api|s|v|\\.well-known)(?:[/?]|$))/(?!/)[A-Za-z0-9._~!$&'()*+,=:@/?-]*$");
    private static final int MAX_LENGTH = 512;

    private ReturnPath() {
    }

    public static boolean isValid(String value) {
        return value != null && value.length() <= MAX_LENGTH && PATTERN.matcher(value).matches();
    }
}
