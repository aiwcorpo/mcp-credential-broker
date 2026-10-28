package pl.aiwcorpo.mcp.broker.authenticator;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Locale;
import java.util.OptionalLong;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** RFC 6238 with the parameters the contract fixes (C4, CC-092): HMAC-SHA-1, 6 digits, 30 s step. */
public final class Totp {

    public static final int STEP_SECONDS = 30;
    private static final int DIGITS_MODULUS = 1_000_000;

    private Totp() {
    }

    public static long stepOf(Instant at) {
        return Math.floorDiv(at.getEpochSecond(), STEP_SECONDS);
    }

    /** The code of one step as six digits, leading zeros kept. */
    public static String code(byte[] seed, long step) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(seed, "HmacSHA1"));
            byte[] hash = mac.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(step).array());
            int offset = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
            return String.format(Locale.ROOT, "%06d", binary % DIGITS_MODULUS);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA-1 is not available", e);
        }
    }

    /**
     * Greatest step of the window {@code now +- windowSteps} whose code equals {@code code}. Every step of the
     * window is compared, in constant time, whether or not an earlier one matched.
     */
    public static OptionalLong matchingStep(byte[] seed, String code, Instant now, int windowSteps) {
        byte[] presented = code.getBytes(StandardCharsets.US_ASCII);
        long current = stepOf(now);
        long match = -1;
        boolean found = false;
        for (long step = current - windowSteps; step <= current + windowSteps; step++) {
            byte[] expected = code(seed, step).getBytes(StandardCharsets.US_ASCII);
            if (MessageDigest.isEqual(expected, presented)) {
                match = step;
                found = true;
            }
        }
        return found ? OptionalLong.of(match) : OptionalLong.empty();
    }
}
