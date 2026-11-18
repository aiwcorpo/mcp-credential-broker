package pl.aiwcorpo.mcp.broker.system;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

/**
 * The addresses an administrator gives: https always, http only on a broker started for development. The broker calls these
 * addresses with its own network position, so an address on the broker host itself or on the link (loopback, link-local
 * with the cloud metadata service, unspecified, multicast) is refused unless {@code broker.allow-loopback-system-urls} is
 * set, which only the tests with local stubs do. Private ranges stay allowed: target systems live there.
 */
public final class SystemUrls {

    /** Name resolution, replaceable in tests. */
    public interface Resolver {
        InetAddress[] resolve(String host) throws UnknownHostException;
    }

    private static final Resolver DNS = InetAddress::getAllByName;

    private SystemUrls() {
    }

    /** @return the parsed address, or null when it is not acceptable */
    public static URI parse(String value, boolean allowPlainHttp) {
        if (value == null || value.length() > 255) {
            return null;
        }
        try {
            URI uri = URI.create(value);
            boolean https = "https".equals(uri.getScheme());
            boolean http = "http".equals(uri.getScheme()) && allowPlainHttp;
            if ((!https && !http) || uri.getHost() == null || uri.getUserInfo() != null || uri.getFragment() != null) {
                return null;
            }
            return uri;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Whether any address the host of {@code uri} resolves to is local; a host that does not resolve counts as local. */
    public static boolean pointsAtLocalAddress(URI uri) {
        return pointsAtLocalAddress(uri, DNS);
    }

    static boolean pointsAtLocalAddress(URI uri, Resolver resolver) {
        InetAddress[] addresses;
        try {
            addresses = resolver.resolve(uri.getHost());
        } catch (UnknownHostException e) {
            return true;
        }
        if (addresses.length == 0) {
            return true;
        }
        for (InetAddress address : addresses) {
            if (isLocal(address)) {
                return true;
            }
        }
        return false;
    }

    static boolean isLocal(InetAddress address) {
        InetAddress embedded = embeddedIpv4(address);
        if (embedded != null) {
            return isLocal(embedded);
        }
        if (address.isLoopbackAddress() || address.isLinkLocalAddress() || address.isAnyLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        // 0.0.0.0/8 reaches the host itself on common stacks, not only 0.0.0.0.
        return address instanceof Inet4Address && address.getAddress()[0] == 0;
    }

    /** The IPv4 address inside an IPv4-mapped (::ffff:a.b.c.d) or IPv4-compatible (::a.b.c.d) IPv6 address, else null. */
    private static InetAddress embeddedIpv4(InetAddress address) {
        if (!(address instanceof Inet6Address)) {
            return null;
        }
        byte[] bytes = address.getAddress();
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) {
                return null;
            }
        }
        boolean mapped = bytes[10] == (byte) 0xff && bytes[11] == (byte) 0xff;
        boolean compatible = bytes[10] == 0 && bytes[11] == 0 && !(bytes[12] == 0 && bytes[13] == 0 && bytes[14] == 0);
        if (!mapped && !compatible) {
            return null;
        }
        try {
            return InetAddress.getByAddress(new byte[] {bytes[12], bytes[13], bytes[14], bytes[15]});
        } catch (UnknownHostException e) {
            return null;
        }
    }
}
