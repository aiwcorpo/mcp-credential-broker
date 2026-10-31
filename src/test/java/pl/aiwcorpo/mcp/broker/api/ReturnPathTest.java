package pl.aiwcorpo.mcp.broker.api;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.broker.support.Contracts;
import tools.jackson.databind.JsonNode;

class ReturnPathTest {

    @Test
    void contractVectors() {
        var files = Contracts.vectors("return-paths");
        assertThat(files).isNotEmpty();
        for (var file : files) {
            JsonNode vector = Contracts.json("test-vectors/return-paths/" + file.getFilename());
            assertThat(ReturnPath.isValid(vector.path("value").stringValue())).as(file.getFilename())
                    .isEqualTo(vector.path("expected").path("valid").asBoolean());
        }
    }

    @Test
    void patternMatchesTheOpenApi() {
        JsonNode schema = Contracts.brokerOpenApi().path("components").path("schemas").path("ReturnPath");
        assertThat(schema.path("pattern").stringValue()).isEqualTo("^(?![^?]*/\\.\\.?(?:[/?]|$))(?!/(?:api|mcp|s|v|\\.well-known)(?:[/?]|$))/(?!/)[A-Za-z0-9._~!$&'()*+,=:@/?-]*$");
        assertThat(schema.path("maxLength").asInt()).isEqualTo(512);
        assertThat(ReturnPath.isValid("/" + "a".repeat(511))).isTrue();
        assertThat(ReturnPath.isValid("/" + "a".repeat(512))).isFalse();
    }
}
