package pl.aiwcorpo.mcp.broker.support;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;

/**
 * Stand-in for the token endpoint of the IdP (WireMock): answers an RFC 8693 token exchange according to the
 * subject token it carries, so each test decides what the IdP says about its own token.
 */
public final class IdpStub {

    private final WireMockServer server = new WireMockServer(options().dynamicPort());

    public IdpStub() {
        server.start();
    }

    public String tokenUrl() {
        return "http://localhost:" + server.port() + "/token";
    }

    /** The IdP issues {@code accessToken} for this subject token; a null {@code expiresIn} leaves the field out. */
    public void issues(String subjectToken, String accessToken, Integer expiresIn) {
        String expires = expiresIn == null ? "" : ",\"expires_in\":" + expiresIn;
        answers(subjectToken, 200, "{\"access_token\":\"" + accessToken + "\",\"issued_token_type\":"
                + "\"urn:ietf:params:oauth:token-type:access_token\",\"token_type\":\"Bearer\"" + expires + "}");
    }

    public void answers(String subjectToken, int status, String body) {
        server.stubFor(post(urlPathEqualTo("/token")).withRequestBody(containing("subject_token=" + encode(subjectToken)))
                .willReturn(aResponse().withStatus(status).withHeader("Content-Type", "application/json").withBody(body)));
    }

    public void refuses(String subjectToken, int status, String error) {
        answers(subjectToken, status, "{\"error\":\"" + error + "\",\"error_description\":\"not for this user\"}");
    }

    public void breaksConnection(String subjectToken) {
        server.stubFor(post(urlPathEqualTo("/token")).withRequestBody(containing("subject_token=" + encode(subjectToken)))
                .willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
    }

    public List<LoggedRequest> requests() {
        return server.findAll(postRequestedFor(urlPathEqualTo("/token")));
    }

    public static Map<String, String> form(LoggedRequest request) {
        Map<String, String> values = new LinkedHashMap<>();
        for (String pair : request.getBodyAsString().split("&")) {
            int eq = pair.indexOf('=');
            values.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return values;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
