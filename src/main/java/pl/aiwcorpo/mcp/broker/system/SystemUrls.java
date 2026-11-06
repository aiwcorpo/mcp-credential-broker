package pl.aiwcorpo.mcp.broker.system;

import java.net.URI;

/** The addresses an administrator gives: https always, http only on a broker started for development. */
public final class SystemUrls {

    private SystemUrls() {
    }

    /** @return the parsed address, or null when it is not acceptable */
    public static URI parse(String value, boolean allowPlainHttp) {
        if (value == null || value.length() > 255) {
            return null;
        }
        try {
            URI uri = URI.create(value);
            boolean https = "https".equals(uri.getScheme());
            boolean http = "http".equals(uri.getScheme()) && allowPlainHttp;
            if ((!https && !http) || uri.getHost() == null || uri.getUserInfo() != null || uri.getFragment() != null) {
                return null;
            }
            return uri;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
