package pl.aiwcorpo.mcp.broker.api;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * C4 PutSecretRequest, with the optional username of a Basic pair (CC-222); unknown properties are rejected by strict JSON binding. {@code expiresAt} stays a
 * string so only the contract's UTC form (suffix Z) is accepted.
 */
public record PutSecretRequest(
        @NotNull @Size(min = 1, max = 4096) String secret,
        @Size(min = 1) @Pattern(regexp = USERNAME) String username,
        @Pattern(regexp = "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,9})?Z$") String expiresAt) {

    /**
     * The character set of backendUser (CC-121: no control, format or surrogate characters, no line or paragraph
     * separators, no invisible fillers) and no colon, which RFC 7617 forbids in a user-id. Same pattern as the contract.
     */
    static final String USERNAME = "^[^:\\p{Cc}\\p{Cf}\\p{Cs}\\u2028\\u2029\\ufdd0-\\ufdef\\ufffe\\uffff\\u034f\\u115f\\u1160\\u3164\\uffa0\\u2800\\ufe00-\\ufe0f]+$";

    /** The contract counts the 255 characters of maxLength as code points; Bean Validation's size counts UTF-16 units. */
    @JsonIgnore
    @AssertTrue
    boolean isUsernameWithinLimit() {
        return username == null || username.codePointCount(0, username.length()) <= 255;
    }

    /** Neither the secret nor the username is printed. */
    @Override
    public String toString() {
        return "PutSecretRequest[expiresAt=" + expiresAt + "]";
    }
}
