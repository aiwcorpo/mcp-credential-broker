package pl.aiwcorpo.mcp.broker.secret;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/** Owner of a stored credential: the user's {@code sub} and the target system. */
public record SecretKey(String sub, String system) {

    public SecretKey {
        Objects.requireNonNull(sub, "sub");
        Objects.requireNonNull(system, "system");
    }

    /**
     * SHA-256 of sub. Used as a path segment because sub is IdP-controlled and may contain characters
     * that are not safe in a secret store path; the hash also keeps raw user ids out of store listings.
     */
    public String subHash() {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(sub.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
