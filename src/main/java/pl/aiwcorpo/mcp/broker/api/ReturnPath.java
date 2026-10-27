package pl.aiwcorpo.mcp.broker.api;

import java.util.regex.Pattern;

/**
 * {@code returnPath} of C4 oauth/start (CC-032): a portal path with an optional query, without percent
 * encoding or backslash, so no decoding pass can turn it into //host. Used when oauth/start lands (M2).
 */
public final class ReturnPath {

    private static final Pattern PATTERN = Pattern.compile("^/(?!/)[A-Za-z0-9._~!$&'()*+,;=:@/?-]*$");
    private static final int MAX_LENGTH = 512;

    private ReturnPath() {
    }

    public static boolean isValid(String value) {
        return value != null && value.length() <= MAX_LENGTH && PATTERN.matcher(value).matches();
    }
}
