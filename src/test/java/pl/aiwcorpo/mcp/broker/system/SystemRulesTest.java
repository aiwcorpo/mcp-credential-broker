package pl.aiwcorpo.mcp.broker.system;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;

/** What a stored system must satisfy (CC-168 and the per adapter checks of the 1.x start-up). */
class SystemRulesTest {

    private static final SystemDefinition.Oauth CLIENT = new SystemDefinition.Oauth("client", URI.create("https://idp.test/authorize"),
            URI.create("https://idp.test/token"), null, List.of());

    private static SystemDefinition system(String id, String adapter, List<CredentialType> types, CredentialType defaultType,
            CredentialScheme scheme, SystemDefinition.Oauth oauth) {
        return new SystemDefinition(id, URI.create("https://backend.test"), adapter, types, defaultType, scheme, oauth, false, null,
                null, null, null, "etag-etag-etag");
    }

    private static String reasonOf(SystemDefinition definition) {
        try {
            SystemRules.check(definition);
            return null;
        } catch (SystemRejectedException e) {
            return e.reason();
        }
    }

    @Test
    void serviceAccountAndTokenExchangeAreNeverMixedWithOtherTypes() {
        assertThat(reasonOf(system("notes", "generic-rest", List.of(CredentialType.SERVICE_ACCOUNT, CredentialType.USER_SECRET),
                CredentialType.SERVICE_ACCOUNT, CredentialScheme.BEARER, null))).isEqualTo("credential_types_mixed");
        assertThat(reasonOf(system("notes", "atlassian-dc", List.of(CredentialType.USER_SECRET, CredentialType.SERVICE_ACCOUNT),
                CredentialType.USER_SECRET, CredentialScheme.BEARER, null))).isEqualTo("credential_types_mixed");
        assertThat(reasonOf(system("notes", "generic-rest", List.of(CredentialType.SERVICE_ACCOUNT, CredentialType.TOKEN_EXCHANGE),
                CredentialType.SERVICE_ACCOUNT, CredentialScheme.BEARER, null))).isEqualTo("credential_types_mixed");
    }

    @Test
    void theAdapterMustFitTheCredentialTypes() {
        assertThat(reasonOf(system("notes", "generic-rest", List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET,
                CredentialScheme.BEARER, null))).isEqualTo("adapter_type_mismatch");
        assertThat(reasonOf(system("notes", "atlassian-dc", List.of(CredentialType.SERVICE_ACCOUNT), CredentialType.SERVICE_ACCOUNT,
                CredentialScheme.BEARER, null))).isEqualTo("adapter_type_mismatch");
        assertThat(reasonOf(system("notes", "gitlab", List.of(CredentialType.TOKEN_EXCHANGE), CredentialType.TOKEN_EXCHANGE,
                CredentialScheme.BEARER, CLIENT))).isEqualTo("adapter_type_mismatch");
        assertThat(reasonOf(system("notes", "atlassian-dc", List.of(CredentialType.USER_OAUTH), CredentialType.USER_OAUTH,
                CredentialScheme.BEARER, CLIENT))).as("Atlassian DC has no OAuth flow here").isEqualTo("adapter_type_mismatch");
    }

    @Test
    void oauthAndTokenExchangeNeedAClient() {
        assertThat(reasonOf(system("notes", "gitlab", List.of(CredentialType.USER_OAUTH), CredentialType.USER_OAUTH,
                CredentialScheme.BEARER, null))).isEqualTo("oauth_required");
        assertThat(reasonOf(system("notes", "opensearch", List.of(CredentialType.TOKEN_EXCHANGE), CredentialType.TOKEN_EXCHANGE,
                CredentialScheme.BEARER, null))).isEqualTo("oauth_required");
    }

    @Test
    void theDefaultTypeMustBeSupportedAndReservedIdsAreRefused() {
        assertThat(reasonOf(system("notes", "gitlab", List.of(CredentialType.USER_SECRET), CredentialType.USER_OAUTH,
                CredentialScheme.BEARER, null))).isEqualTo("default_type_not_supported");
        assertThat(reasonOf(system("gateway", "gitlab", List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET,
                CredentialScheme.BEARER, null))).isEqualTo("system_reserved");
        assertThat(SystemIds.isValid("notes")).isTrue();
        assertThat(SystemIds.isValid("a")).isFalse();
        assertThat(SystemIds.isValid("Notes")).isFalse();
        assertThat(SystemIds.isValid("prometheus")).isFalse();
    }

    @Test
    void validCombinationsPass() {
        assertThat(reasonOf(system("jira", "atlassian-dc", List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET,
                CredentialScheme.BEARER, null))).isNull();
        assertThat(reasonOf(system("gitlab", "gitlab", List.of(CredentialType.USER_OAUTH, CredentialType.USER_SECRET),
                CredentialType.USER_OAUTH, CredentialScheme.BEARER, CLIENT))).isNull();
        assertThat(reasonOf(system("search", "opensearch", List.of(CredentialType.TOKEN_EXCHANGE), CredentialType.TOKEN_EXCHANGE,
                CredentialScheme.BEARER, CLIENT))).isNull();
        assertThat(reasonOf(system("desk", "generic-rest", List.of(CredentialType.SERVICE_ACCOUNT), CredentialType.SERVICE_ACCOUNT,
                CredentialScheme.BEARER, null))).isNull();
    }

    @Test
    void aUserSecretSystemTakesBearerOrBasic() {
        assertThat(reasonOf(system("jira", "atlassian-dc", List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET,
                CredentialScheme.TOKEN, null))).isEqualTo("secret_scheme_not_supported");
    }

    @Test
    void aBasicUserSecretNeedsTheUserSecretType() {
        assertThatThrownBy(() -> new BrokerProperties.SystemConfig(URI.create("http://gitlab.test"), "gitlab",
                List.of(CredentialType.USER_OAUTH), CredentialType.USER_OAUTH, CredentialScheme.BEARER, List.of(),
                Duration.ofSeconds(1), null, null, CredentialScheme.BASIC, null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BrokerProperties.SystemConfig(URI.create("http://jira.test"), "atlassian-dc",
                List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, CredentialScheme.BEARER, List.of(),
                Duration.ofSeconds(1), null, null, CredentialScheme.TOKEN, null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BrokerProperties.SystemConfig(URI.create("http://jira.test"), "atlassian-dc",
                List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, CredentialScheme.TOKEN, List.of(),
                Duration.ofSeconds(1), null, null, null, null)).as("no guessing Bearer for a Token system").isInstanceOf(IllegalArgumentException.class);
    }
}
