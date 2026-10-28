package pl.aiwcorpo.mcp.broker.credential;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.io.Resource;

import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.system.BackendIdentity;
import tools.jackson.databind.JsonNode;

/** All vectors of test-vectors/whoami-identity (C4.1) through the broker's identity rule. */
class IdentityRuleVectorTest {

    static Stream<Arguments> vectors() {
        List<Resource> files = Contracts.vectors("whoami-identity");
        assertThat(files).hasSize(12);
        return files.stream().map(file -> {
            try (var in = file.getInputStream()) {
                return Arguments.of(file.getFilename(), Contracts.JSON.readTree(in));
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void vector(String name, JsonNode vector) {
        JsonNode input = vector.path("input");
        String mapping = input.path("mapping").stringValue();
        Map<String, Object> sso = new HashMap<>();
        input.path("sso").propertyNames().forEach(field -> {
            JsonNode value = input.path("sso").path(field);
            sso.put(field, value.isBoolean() ? (Object) value.asBoolean() : value.stringValue());
        });
        String systemIdentity = input.path("systemIdentity").stringValue();
        BackendIdentity backend = "email".equals(mapping)
                ? new BackendIdentity("unrelated-login", systemIdentity)
                : new BackendIdentity(systemIdentity, "unrelated@corp.test");

        assertThat(IdentityRule.matches(mapping, sso, backend)).as(vector.path("description").stringValue())
                .isEqualTo(vector.path("expected").path("match").asBoolean());
    }

    @Test
    void aMissingClaimOrBackendValueNeverMatches() {
        assertThat(IdentityRule.matches("preferred_username", Map.of(), new BackendIdentity("alice", null))).isFalse();
        assertThat(IdentityRule.matches("email", Map.of("email", "a@corp.test", "email_verified", true),
                new BackendIdentity("a", null))).isFalse();
        assertThat(IdentityRule.matches("preferred_username", Map.of("preferred_username", 7), new BackendIdentity("7", null)))
                .isFalse();
    }
}
