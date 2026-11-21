package pl.aiwcorpo.mcp.broker.tracing;

import java.util.regex.Pattern;

/**
 * The {@code uri} tag of an HTTP observation is meant to be a template such as {@code /users/{id}}. A caller that builds the URL by
 * concatenation passes the finished string as the "template", so the tag may hold a query, credentials or identifiers. A query or user
 * info is dropped when it consists of template variables only; when it holds literal text the string was not a template and the tag
 * becomes {@link #UNKNOWN}.
 */
public final class UriLabel {

    public static final String UNKNOWN = "unknown";

    private static final Pattern VARIABLE_ONLY_QUERY = Pattern.compile("([^=&{}]*=)?\\{[^{}]*}(&([^=&{}]*=)?\\{[^{}]*})*");
    private static final Pattern VARIABLE_ONLY_USERINFO = Pattern.compile("\\{[^{}]*}(:\\{[^{}]*})?");

    private UriLabel() {
    }

    public static String of(String uriTag) {
        if (uriTag == null || uriTag.isEmpty() || "none".equals(uriTag)) {
            return uriTag;
        }
        String rest = uriTag;
        int fragment = rest.indexOf('#');
        if (fragment >= 0) {
            if (!rest.substring(fragment + 1).isEmpty()) {
                return UNKNOWN;
            }
            rest = rest.substring(0, fragment);
        }
        int query = rest.indexOf('?');
        if (query >= 0) {
            String queryText = rest.substring(query + 1);
            if (!queryText.isEmpty() && !VARIABLE_ONLY_QUERY.matcher(queryText).matches()) {
                return UNKNOWN;
            }
            rest = rest.substring(0, query);
        }
        int scheme = rest.indexOf("://");
        if (scheme >= 0) {
            int authorityEnd = rest.indexOf('/', scheme + 3);
            String authority = authorityEnd < 0 ? rest.substring(scheme + 3) : rest.substring(scheme + 3, authorityEnd);
            int at = authority.lastIndexOf('@');
            if (at >= 0) {
                if (!VARIABLE_ONLY_USERINFO.matcher(authority.substring(0, at)).matches()) {
                    return UNKNOWN;
                }
                rest = rest.substring(0, scheme + 3) + authority.substring(at + 1) + (authorityEnd < 0 ? "" : rest.substring(authorityEnd));
            }
        }
        return rest;
    }
}
