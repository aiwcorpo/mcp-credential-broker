package pl.aiwcorpo.mcp.broker.support;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.MappingBuilder;
import com.github.tomakehurst.wiremock.stubbing.StubMapping;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;

/**
 * Stand-in for GitLab as an OAuth provider (WireMock) until the mock of the dev stack has one:
 * /oauth/token for authorization codes and refresh tokens, /oauth/revoke, and /api/v4/user (whoami) that
 * names the owner of an access token or PAT. Every grant gets unique token values, so tests can look for
 * them in logs and stored data.
 */
public final class GitLabStub {

    /** Tokens behind one authorization code or refresh. */
    public record Grant(String user, String code, String accessToken, String refreshToken) {
    }

    private final WireMockServer server = new WireMockServer(options().dynamicPort());
    private final AtomicInteger counter = new AtomicInteger();
    private StubMapping revoke;

    public GitLabStub() {
        server.start();
    }

    public String url() {
        return "http://localhost:" + server.port();
    }

    /** An authorization code the provider will exchange for tokens of {@code user}. */
    public Grant issueCode(String user, int expiresInSeconds) {
        int n = counter.incrementAndGet();
        Grant grant = new Grant(user, "code-" + user + "-" + n, "gl-at-" + user + "-" + n, "gl-rt-" + user + "-" + n);
        server.stubFor(tokenRequest("authorization_code", "code", grant.code()).willReturn(tokens(grant, expiresInSeconds)));
        whoami(grant.accessToken(), user);
        return grant;
    }

    /** The provider answers a refresh with {@code old.refreshToken()} by rotating to a new pair. */
    public Grant rotateOnRefresh(Grant old, int expiresInSeconds, int delayMillis) {
        int n = counter.incrementAndGet();
        Grant next = new Grant(old.user(), null, "gl-at-" + old.user() + "-" + n, "gl-rt-" + old.user() + "-" + n);
        server.stubFor(tokenRequest("refresh_token", "refresh_token", old.refreshToken())
                .willReturn(tokens(next, expiresInSeconds).withFixedDelay(delayMillis)));
        whoami(next.accessToken(), old.user());
        return next;
    }

    public void refreshAnswers(Grant old, int status, String error) {
        server.stubFor(tokenRequest("refresh_token", "refresh_token", old.refreshToken())
                .willReturn(aResponse().withStatus(status).withHeader("Content-Type", "application/json")
                        .withBody("{\"error\":\"" + error + "\"}")));
    }

    public void codeAnswers(String code, int status, String error, int delayMillis) {
        server.stubFor(tokenRequest("authorization_code", "code", code)
                .willReturn(aResponse().withStatus(status).withHeader("Content-Type", "application/json")
                        .withFixedDelay(delayMillis).withBody("{\"error\":\"" + error + "\"}")));
    }

    /** A personal access token that belongs to {@code user}. */
    public void pat(String pat, String user) {
        whoami(pat, user);
    }

    /** whoami of this token answers a JSON body far over what the broker reads. */
    public void oversizedWhoami(String bearer) {
        server.stubFor(get(urlPathEqualTo("/api/v4/user")).atPriority(1).withHeader("Authorization", equalTo("Bearer " + bearer))
                .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json")
                        .withBody("{\"username\":\"" + "x".repeat(300_000) + "\"}")));
    }

    /** whoami of this token starts answering at once but sends the body in drops for much longer than the broker waits. */
    public void trickledWhoami(String bearer) {
        server.stubFor(get(urlPathEqualTo("/api/v4/user")).atPriority(1).withHeader("Authorization", equalTo("Bearer " + bearer))
                .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json")
                        .withBody("{\"id\":7,\"username\":\"alice\",\"email\":\"alice@corp.test\"}")
                        .withChunkedDribbleDelay(10, 8000)));
    }

    public void whoamiFails(String bearer, int status) {
        server.stubFor(get(urlPathEqualTo("/api/v4/user")).atPriority(1).withHeader("Authorization", equalTo("Bearer " + bearer))
                .willReturn(aResponse().withStatus(status).withBody("{}")));
    }

    public void revokeAccepts() {
        revokeAnswers(200);
    }

    public void revokeAnswers(int status) {
        if (revoke != null) {
            server.removeStubMapping(revoke);
        }
        revoke = server.stubFor(post(urlPathEqualTo("/oauth/revoke")).willReturn(aResponse().withStatus(status).withBody("{}")));
    }

    public List<Map<String, String>> tokenRequests() {
        return forms("/oauth/token");
    }

    public List<Map<String, String>> revokeRequests() {
        return forms("/oauth/revoke");
    }

    public int whoamiCalls() {
        return server.countRequestsMatching(com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor(urlPathEqualTo("/api/v4/user")).build())
                .getCount();
    }

    /** Token requests of one grant type that carried this value of the named parameter. */
    public List<Map<String, String>> tokenRequests(String grantType, String parameter, String value) {
        return tokenRequests().stream()
                .filter(form -> grantType.equals(form.get("grant_type")) && value.equals(form.get(parameter)))
                .toList();
    }

    private void whoami(String bearer, String user) {
        server.stubFor(get(urlPathEqualTo("/api/v4/user")).withHeader("Authorization", equalTo("Bearer " + bearer))
                .willReturn(aResponse().withStatus(200).withHeader("Content-Type", "application/json")
                        .withBody("{\"id\":7,\"username\":\"" + user + "\",\"email\":\"" + user + "@corp.test\",\"state\":\"active\"}")));
        server.stubFor(get(urlPathEqualTo("/api/v4/user")).atPriority(10)
                .willReturn(aResponse().withStatus(401).withHeader("Content-Type", "application/json")
                        .withBody("{\"message\":\"401 Unauthorized\"}")));
    }

    private static MappingBuilder tokenRequest(String grantType, String parameter, String value) {
        return post(urlPathEqualTo("/oauth/token"))
                .withRequestBody(matching("(.*&)?grant_type=" + grantType + "(&.*)?"))
                .withRequestBody(matching("(.*&)?" + parameter + "=" + value + "(&.*)?"));
    }

    private static com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder tokens(Grant grant, int expiresIn) {
        String refresh = grant.refreshToken() == null ? "" : ",\"refresh_token\":\"" + grant.refreshToken() + "\"";
        return aResponse().withStatus(200).withHeader("Content-Type", "application/json")
                .withBody("{\"access_token\":\"" + grant.accessToken() + "\",\"token_type\":\"Bearer\",\"expires_in\":" + expiresIn
                        + refresh + ",\"created_at\":1790000000}");
    }

    private List<Map<String, String>> forms(String path) {
        return server.findAll(postRequestedFor(urlPathEqualTo(path))).stream().map(GitLabStub::form).toList();
    }

    private static Map<String, String> form(LoggedRequest request) {
        Map<String, String> values = new LinkedHashMap<>();
        for (String pair : request.getBodyAsString().split("&")) {
            int eq = pair.indexOf('=');
            values.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return values;
    }
}
