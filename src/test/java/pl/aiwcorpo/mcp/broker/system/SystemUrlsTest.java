package pl.aiwcorpo.mcp.broker.system;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

import org.junit.jupiter.api.Test;

/** The addresses an administrator may give: https always, http only on a broker started for development. */
class SystemUrlsTest {

    @Test
    void aProductionBrokerAcceptsOnlyHttps() {
        assertThat(SystemUrls.parse("https://jira.internal", false)).isNotNull();
        assertThat(SystemUrls.parse("http://jira.internal", false)).isNull();
        assertThat(SystemUrls.parse("HTTP://jira.internal", false)).isNull();
        assertThat(SystemUrls.parse("ftp://jira.internal", false)).isNull();
        assertThat(SystemUrls.parse("//jira.internal", false)).isNull();
        assertThat(SystemUrls.parse("jira.internal", false)).isNull();
    }

    @Test
    void aDevelopmentBrokerAlsoAcceptsHttp() {
        assertThat(SystemUrls.parse("http://localhost:8080", true)).isNotNull();
        assertThat(SystemUrls.parse("https://localhost:8080", true)).isNotNull();
        assertThat(SystemUrls.parse("ftp://localhost", true)).isNull();
    }

    @Test
    void credentialsFragmentsAndGarbageAreRefused() {
        assertThat(SystemUrls.parse("https://user:pass@jira.internal", true)).isNull();
        assertThat(SystemUrls.parse("https://jira.internal/#frag", true)).isNull();
        assertThat(SystemUrls.parse("https://jira internal", true)).isNull();
        assertThat(SystemUrls.parse(null, true)).isNull();
        assertThat(SystemUrls.parse("https://" + "a".repeat(300), true)).isNull();
    }

    @Test
    void addressesOnTheBrokerHostOrItsLinkAreLocal() {
        for (String host : new String[] {"127.0.0.1", "127.8.9.10", "[::1]", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "[::127.0.0.1]",
                "169.254.169.254", "[fe80::1]", "[::ffff:169.254.169.254]", "0.0.0.0", "0.1.2.3", "[::]", "224.0.0.1", "[ff02::1]"}) {
            assertThat(SystemUrls.pointsAtLocalAddress(URI.create("https://" + host + ":8443/api"))).as(host).isTrue();
        }
    }

    @Test
    void privateAndPublicAddressesAreNot() {
        for (String host : new String[] {"10.0.0.5", "172.16.0.1", "192.168.1.10", "[fd00::5]", "[::ffff:10.0.0.5]", "8.8.8.8"}) {
            assertThat(SystemUrls.pointsAtLocalAddress(URI.create("https://" + host))).as(host).isFalse();
        }
    }

    @Test
    void everyAddressANameResolvesToIsChecked() throws UnknownHostException {
        InetAddress internal = InetAddress.getByName("10.0.0.5");
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        URI named = URI.create("https://jira.internal");
        assertThat(SystemUrls.pointsAtLocalAddress(named, host -> new InetAddress[] {internal})).isFalse();
        assertThat(SystemUrls.pointsAtLocalAddress(named, host -> new InetAddress[] {internal, loopback})).isTrue();
        assertThat(SystemUrls.pointsAtLocalAddress(named, host -> {
            throw new UnknownHostException(host);
        })).as("a name that does not resolve").isTrue();
    }
}
