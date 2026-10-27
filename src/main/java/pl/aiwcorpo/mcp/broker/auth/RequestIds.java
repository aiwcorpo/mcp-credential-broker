package pl.aiwcorpo.mcp.broker.auth;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.UUID;

/** UUIDv7 request ids (RFC 9562) for requests that do not bring one (C2 rid, C8 requestId). */
public final class RequestIds {

    private static final SecureRandom RANDOM = new SecureRandom();

    private RequestIds() {
    }

    public static String next(Clock clock) {
        long millis = clock.millis();
        long randA = RANDOM.nextInt(1 << 12);
        long randB = RANDOM.nextLong() & 0x3FFF_FFFF_FFFF_FFFFL;
        long msb = (millis << 16) | (0x7L << 12) | randA;
        long lsb = 0x8000_0000_0000_0000L | randB;
        return new UUID(msb, lsb).toString();
    }

    public static boolean isValid(String value) {
        return value != null && InternalJwtVerifier.REQUEST_ID.matcher(value).matches();
    }
}
