package pl.aiwcorpo.mcp.broker.api;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/** Request bodies of the authenticator operations (C4); unknown properties are rejected by strict binding. */
public final class AuthenticatorRequests {

    private AuthenticatorRequests() {
    }

    /** The code is credential material: it is not part of toString. */
    public record Verify(@NotNull @Pattern(regexp = "^[0-9]{6}$") String code) {

        @Override
        public String toString() {
            return "Verify[]";
        }
    }

    public record ConfirmEnrollment(@NotNull @Pattern(regexp = "^[A-Za-z0-9_-]{16,128}$") String enrollmentId,
            @NotNull @Pattern(regexp = "^[0-9]{6}$") String code) {

        @Override
        public String toString() {
            return "ConfirmEnrollment[enrollmentId=" + enrollmentId + "]";
        }
    }
}
