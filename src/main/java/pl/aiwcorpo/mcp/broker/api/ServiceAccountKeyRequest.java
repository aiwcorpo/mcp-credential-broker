package pl.aiwcorpo.mcp.broker.api;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * C4 ServiceAccountKeyRequest (CC-251): the key of the platform's account in a target system, either {@code value} or
 * {@code username} with {@code password}. {@code expiresAt} stays a string so only the contract's UTC form (suffix Z) is
 * accepted. Nothing in it is ever printed.
 */
public record ServiceAccountKeyRequest(
        @Size(min = 1, max = 4096) @Pattern(regexp = "^[!-~]+$") String value,
        @Size(min = 1) @Pattern(regexp = PutSecretRequest.USERNAME) String username,
        @Size(min = 1, max = 4096) String password,
        @Pattern(regexp = "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,9})?Z$") String expiresAt) {

    @JsonIgnore
    @AssertTrue
    boolean isExactlyOneForm() {
        boolean pair = username != null && password != null;
        boolean partOfPair = username != null || password != null;
        return value != null ? !partOfPair : pair;
    }

    /** The contract counts the 255 characters of maxLength as code points; Bean Validation's size counts UTF-16 units. */
    @JsonIgnore
    @AssertTrue
    boolean isUsernameWithinLimit() {
        return username == null || username.codePointCount(0, username.length()) <= 255;
    }

    @Override
    public String toString() {
        return "ServiceAccountKeyRequest[expiresAt=" + expiresAt + "]";
    }
}
