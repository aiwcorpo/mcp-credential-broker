package pl.aiwcorpo.mcp.broker.system;

import static org.assertj.core.api.Assertions.assertThat;

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
}
