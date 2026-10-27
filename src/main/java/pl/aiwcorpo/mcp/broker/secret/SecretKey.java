package pl.aiwcorpo.mcp.broker.secret;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Location of one stored credential value: its owner (the user's {@code sub} and the target system) and
 * the version written by one PUT. {@code version} is null only for values stored before versions existed.
 */
public record SecretKey(String sub, String system, String version) {

    private static final SecureRandom RANDOM = new SecureRandom();

    public SecretKey {
        Objects.requireNonNull(sub, "sub");
        Objects.requireNonNull(system, "system");
    }

    public static SecretKey newVersion(String sub, String system) {
        byte[] id = new byte[12];
        RANDOM.nextBytes(id);
        return new SecretKey(sub, system, HexFormat.of().formatHex(id));
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

    /** Path below the store's prefix: {@code <sha256(sub)>/<system>[/<version>]}. */
    public String relativePath() {
        return subHash() + "/" + system + (version == null ? "" : "/" + version);
    }
}
