package pl.aiwcorpo.mcp.broker.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.net.http.HttpClient;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import pl.aiwcorpo.mcp.broker.secret.OAuthClientSecrets;
import pl.aiwcorpo.mcp.broker.secret.OpenBaoClient;
import pl.aiwcorpo.mcp.broker.support.AuditLines;
import pl.aiwcorpo.mcp.broker.support.TestEnvironment;
import pl.aiwcorpo.mcp.broker.system.LegacySystemImport;
import pl.aiwcorpo.mcp.broker.system.SystemDefinition;
import pl.aiwcorpo.mcp.broker.system.SystemRejectedException;
import pl.aiwcorpo.mcp.broker.system.SystemRepository;
import tools.jackson.databind.json.JsonMapper;

/** The one-time move of the broker.systems.* properties of 1.x into the table, against an empty database of its own. */
@ExtendWith(OutputCaptureExtension.class)
class LegacySystemImportIntegrationTest {

    private static final TestEnvironment env = TestEnvironment.get();

    private final Clock clock = Clock.systemUTC();
    private final String database = "import_" + UUID.randomUUID().toString().replace("-", "");
    private final String jiraId = "ij" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    private final String gitlabId = "ig" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    private final String searchId = "is" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    private final OAuthClientSecrets secrets = new OAuthClientSecrets(
            new OpenBaoClient(new BrokerProperties.OpenBao(URI.create(env.openBaoUrl()), TestEnvironment.BAO_ROLE_ID,
                    TestEnvironment.BAO_SECRET_ID, "secret", "mcp/connections", "mcp/oauth-clients", "mcp/service-accounts", "transit",
                    "mcp-credential-broker", Duration.ofSeconds(5)), HttpClient.newHttpClient(), JsonMapper.builder().build(), clock),
            "secret", "mcp/oauth-clients", clock);

    private SystemRepository emptyRepository() throws SQLException {
        try (Connection admin = DriverManager.getConnection(env.postgres.getJdbcUrl(), env.postgres.getUsername(), env.postgres.getPassword())) {
            admin.createStatement().execute("create database " + database);
        }
        String url = env.postgres.getJdbcUrl().replaceFirst("/[^/?]+(\\?|$)", "/" + database + "$1");
        DriverManagerDataSource dataSource = new DriverManagerDataSource(url, env.postgres.getUsername(), env.postgres.getPassword());
        Flyway.configure().dataSource(dataSource).locations("classpath:db/migration").load().migrate();
        return new SystemRepository(JdbcClient.create(dataSource), JsonMapper.builder().build());
    }

    private Map<String, BrokerProperties.SystemConfig> legacy() {
        BrokerProperties.SystemConfig jira = new BrokerProperties.SystemConfig(URI.create("https://jira.internal"), "atlassian-dc",
                List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, CredentialScheme.BEARER, List.of(),
                Duration.ofSeconds(5), null, null, null, null);
        BrokerProperties.SystemConfig gitlab = new BrokerProperties.SystemConfig(URI.create("https://gitlab.internal"), "gitlab",
                List.of(CredentialType.USER_OAUTH, CredentialType.USER_SECRET), CredentialType.USER_OAUTH, CredentialScheme.BEARER,
                List.of("read_api", "api"), Duration.ofSeconds(3),
                new BrokerProperties.OAuth("mcp-broker", "dev-only-client-secret-" + gitlabId, null, null,
                        URI.create("https://gitlab.internal/oauth/revoke-all")),
                null, null, BrokerProperties.Deployment.DC);
        BrokerProperties.SystemConfig search = new BrokerProperties.SystemConfig(URI.create("https://search.internal"), "opensearch",
                List.of(CredentialType.TOKEN_EXCHANGE), CredentialType.TOKEN_EXCHANGE, CredentialScheme.BEARER, List.of(),
                Duration.ofSeconds(2), null, new BrokerProperties.TokenExchange("mcp-credential-broker", null,
                        URI.create("https://idp.internal/token"), "opensearch", List.of("aud-scope")), null, null);
        return Map.of(jiraId, jira, gitlabId, gitlab, searchId, search);
    }

    @Test
    void anEmptyTableIsFilledOnceAndTheClientSecretsStayInOpenBao(CapturedOutput output) throws Exception {
        env.bao("POST", "secret/data/mcp/oauth-clients/" + searchId, "{\"data\":{\"client_secret\":\"already-in-openbao\"}}");
        SystemRepository repository = emptyRepository();
        LegacySystemImport importer = new LegacySystemImport(repository, secrets, new AuditLog("mcp-credential-broker", clock), clock);

        assertThat(importer.run(legacy())).isEqualTo(3);

        SystemDefinition gitlab = repository.find(gitlabId).orElseThrow();
        assertThat(gitlab.oauth().authorizeUrl()).hasToString("https://gitlab.internal/oauth/authorize");
        assertThat(gitlab.oauth().tokenUrl()).hasToString("https://gitlab.internal/oauth/token");
        assertThat(gitlab.oauth().revokeUrl()).hasToString("https://gitlab.internal/oauth/revoke-all");
        assertThat(gitlab.oauth().scopes()).containsExactly("read_api", "api");
        assertThat(gitlab.timeout()).isEqualTo(Duration.ofSeconds(3));
        assertThat(gitlab.deployment()).isEqualTo(BrokerProperties.Deployment.DC);
        assertThat(gitlab.clientSecretSet()).isTrue();
        assertThat(env.bao("GET", "secret/data/mcp/oauth-clients/" + gitlabId, null).body())
                .contains("dev-only-client-secret-" + gitlabId);

        SystemDefinition search = repository.find(searchId).orElseThrow();
        assertThat(search.exchangeAudience()).isEqualTo("opensearch");
        assertThat(search.oauth().clientId()).isEqualTo("mcp-credential-broker");
        assertThat(search.oauth().tokenUrl()).hasToString("https://idp.internal/token");
        assertThat(search.oauth().scopes()).containsExactly("aud-scope");
        assertThat(search.clientSecretSet()).as("found where 1.x kept it").isTrue();

        SystemDefinition jira = repository.find(jiraId).orElseThrow();
        assertThat(jira.oauth()).isNull();
        assertThat(jira.clientSecretSet()).isFalse();
        assertThat(jira.etag()).matches("^[A-Za-z0-9_-]{8,128}$");

        assertThat(AuditLines.all(output)).filteredOn(event -> "system_imported".equals(event.path("reason").stringValue()))
                .extracting(event -> event.path("server").stringValue())
                .containsExactlyInAnyOrder("mcp-" + jiraId, "mcp-" + gitlabId, "mcp-" + searchId);
        assertThat(output.getAll()).doesNotContain("dev-only-client-secret-" + gitlabId);

        repository.delete(jiraId);
        repository.delete(gitlabId);
        repository.delete(searchId);
        assertThat(repository.isEmpty()).isTrue();
        assertThat(importer.run(legacy())).as("not again once it ran, also when every system was deleted").isZero();
        assertThat(repository.isEmpty()).isTrue();
    }

    @Test
    void aTableThatHasSystemsIsNotTouched() throws Exception {
        SystemRepository repository = emptyRepository();
        SystemDefinition existing = new SystemDefinition("notes", URI.create("https://notes.internal"), "atlassian-dc",
                List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, CredentialScheme.BEARER, null, false, null, null, null,
                null, SystemDefinition.newEtag());
        assertThat(repository.insert(existing, clock.instant())).isTrue();
        LegacySystemImport importer = new LegacySystemImport(repository, secrets, new AuditLog("mcp-credential-broker", clock), clock);

        assertThat(importer.run(legacy())).isZero();

        assertThat(repository.findAll()).extracting(SystemDefinition::id).containsExactly("notes");
        assertThat(importer.run(Map.of())).isZero();
    }

    @Test
    void aConfigurationTheNewRulesRefuseStopsTheImport() throws Exception {
        SystemRepository repository = emptyRepository();
        LegacySystemImport importer = new LegacySystemImport(repository, secrets, new AuditLog("mcp-credential-broker", clock), clock);
        BrokerProperties.SystemConfig reserved = new BrokerProperties.SystemConfig(URI.create("https://x.internal"), "atlassian-dc",
                List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, CredentialScheme.BEARER, List.of(),
                Duration.ofSeconds(5), null, null, null, null);

        assertThatThrownBy(() -> importer.run(Map.of("gateway", reserved))).isInstanceOf(SystemRejectedException.class);
        assertThat(repository.isEmpty()).isTrue();
    }
}
