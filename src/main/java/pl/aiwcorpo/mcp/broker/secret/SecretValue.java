package pl.aiwcorpo.mcp.broker.secret;

import java.util.Objects;

/**
 * A secret in memory. toString never reveals it, so a secret that ends up in a log statement, an exception
 * message or a debugger watch by accident prints as a mask. {@link #reveal()} is called only where the
 * value has to leave the process: the whoami call, the secret store and the resolve response.
 */
public final class SecretValue {

    private final String value;

    private SecretValue(String value) {
        this.value = value;
    }

    public static SecretValue of(String value) {
        Objects.requireNonNull(value, "value");
        if (value.isEmpty()) {
            throw new IllegalArgumentException("empty secret");
        }
        return new SecretValue(value);
    }

    public String reveal() {
        return value;
    }

    /** Header-safe token alphabet: visible ASCII without spaces, so it cannot inject or split headers. */
    public boolean isHeaderToken() {
        return value.chars().allMatch(c -> c > 0x20 && c < 0x7f);
    }

    @Override
    public String toString() {
        return "SecretValue[***]";
    }
}
