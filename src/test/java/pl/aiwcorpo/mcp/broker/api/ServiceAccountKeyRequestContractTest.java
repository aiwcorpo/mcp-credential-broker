package pl.aiwcorpo.mcp.broker.api;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import tools.jackson.databind.JsonNode;

class ServiceAccountKeyRequestContractTest {

    private static final String VALUE_PATTERN = "^[!-~]+$";

    private static JsonNode schema() {
        return Contracts.brokerOpenApi().path("components").path("schemas").path("ServiceAccountKeyRequest").path("properties");
    }

    @Test
    void thePatternsAreTheOnesOfTheContract() {
        assertThat(schema().path("value").path("pattern").stringValue()).isEqualTo(VALUE_PATTERN);
        assertThat(schema().path("username").path("pattern").stringValue()).isEqualTo(PutSecretRequest.USERNAME);
    }

    @Test
    void exactlyOneOfValueAndTheLoginPairIsAccepted() {
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            assertThat(validator.validate(new ServiceAccountKeyRequest("token-0001", null, null, null))).isEmpty();
            assertThat(validator.validate(new ServiceAccountKeyRequest(null, "svc-mcp", "pw", "2030-01-01T00:00:00Z"))).isEmpty();
            assertThat(validator.validate(new ServiceAccountKeyRequest(null, null, null, null))).as("nothing").isNotEmpty();
            assertThat(validator.validate(new ServiceAccountKeyRequest("token-0001", "svc-mcp", "pw", null))).as("both").isNotEmpty();
            assertThat(validator.validate(new ServiceAccountKeyRequest("token-0001", "svc-mcp", null, null))).as("value and login").isNotEmpty();
            assertThat(validator.validate(new ServiceAccountKeyRequest(null, "svc-mcp", null, null))).as("login alone").isNotEmpty();
            assertThat(validator.validate(new ServiceAccountKeyRequest(null, null, "pw", null))).as("password alone").isNotEmpty();
        }
    }

    @Test
    void theValueIsVisibleAsciiWithoutSpacesAndTheExpiryIsUtc() {
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            Validator validator = factory.getValidator();
            assertThat(validator.validate(new ServiceAccountKeyRequest("two words", null, null, null))).isNotEmpty();
            assertThat(validator.validate(new ServiceAccountKeyRequest("tab\there", null, null, null))).isNotEmpty();
            assertThat(validator.validate(new ServiceAccountKeyRequest("k" + (char) 0xf3, null, null, null))).isNotEmpty();
            assertThat(validator.validate(new ServiceAccountKeyRequest("a".repeat(4097), null, null, null))).isNotEmpty();
            assertThat(validator.validate(new ServiceAccountKeyRequest(null, "svc:mcp", "pw", null))).as("colon in login").isNotEmpty();
            assertThat(validator.validate(new ServiceAccountKeyRequest("k", null, null, "2030-01-01T00:00:00+01:00"))).isNotEmpty();
            assertThat(validator.validate(new ServiceAccountKeyRequest("k", null, null, "2030-01-01"))).isNotEmpty();
        }
    }

    @Test
    void nothingOfTheKeyIsPrinted() {
        String printed = new ServiceAccountKeyRequest("value-secret-0001", "login-secret", "password-secret", "2030-01-01T00:00:00Z").toString();
        assertThat(printed).doesNotContain("value-secret-0001", "login-secret", "password-secret");
    }
}
