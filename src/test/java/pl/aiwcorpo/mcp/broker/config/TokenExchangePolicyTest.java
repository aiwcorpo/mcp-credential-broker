package pl.aiwcorpo.mcp.broker.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

/** Which audiences a token-exchange system may name. */
class TokenExchangePolicyTest {

    @Test
    void nothingIsAllowedByDefault() {
        assertThat(new BrokerProperties.TokenExchangePolicy(null).allows("opensearch")).isFalse();
        assertThat(new BrokerProperties.TokenExchangePolicy(List.of()).allows("opensearch")).isFalse();
        assertThat(new BrokerProperties.TokenExchangePolicy(List.of(" ", "")).allows("opensearch")).isFalse();
    }

    @Test
    void anEntryWithoutAStarIsAnExactValue() {
        BrokerProperties.TokenExchangePolicy policy = new BrokerProperties.TokenExchangePolicy(List.of("opensearch", "reports-api"));
        assertThat(policy.allows("opensearch")).isTrue();
        assertThat(policy.allows("reports-api")).isTrue();
        assertThat(policy.allows("opensearch2")).isFalse();
        assertThat(policy.allows("Opensearch")).isFalse();
        assertThat(policy.allows("xopensearch")).isFalse();
        assertThat(policy.allows("")).isFalse();
        assertThat(policy.allows(null)).isFalse();
    }

    @Test
    void aStarStandsForAnyCharactersAndNothingElseIsAPattern() {
        BrokerProperties.TokenExchangePolicy policy = new BrokerProperties.TokenExchangePolicy(List.of("aud-*", "https://*.corp.test/api", "a.b"));
        assertThat(policy.allows("aud-notes")).isTrue();
        assertThat(policy.allows("aud-")).isTrue();
        assertThat(policy.allows("aud")).isFalse();
        assertThat(policy.allows("xaud-notes")).isFalse();
        assertThat(policy.allows("https://search.corp.test/api")).isTrue();
        assertThat(policy.allows("https://search.corp.test/api/extra")).isFalse();
        assertThat(policy.allows("https://corp.test/api")).isFalse();
        assertThat(policy.allows("a.b")).isTrue();
        assertThat(policy.allows("aXb")).as("a dot is a dot").isFalse();
    }

    @Test
    void aLoneStarAllowsEveryAudience() {
        assertThat(new BrokerProperties.TokenExchangePolicy(List.of("*")).allows("anything")).isTrue();
        assertThat(new BrokerProperties.TokenExchangePolicy(List.of("*")).allows("")).as("an audience is never empty").isFalse();
    }
}
