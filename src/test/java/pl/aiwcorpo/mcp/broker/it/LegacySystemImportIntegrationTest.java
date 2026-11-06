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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.ConnectionRepository;
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
    private static final URI IDP_TOKEN_URL = URI.create("https://idp.internal/token");

    private final Clock clock = Clock.systemUTC();
    private final String database = "import_" + UUID.randomUUID().toString().replace("-", "");
    private final String gitlabId = "ig" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    private final String searchId = "is" + UUID.randomUUID().toString().replace("-", "").substring(0, 8);

    private final OAuthClientSecrets secrets = new OAuthClientSecrets(
            new OpenBaoClient(new BrokerProperties.OpenBao(URI.create(env.openBaoUrl()), TestEnvironment.BAO_ROLE_ID,
                    TestEnvironment.BAO_SECRET_ID, "secret", "mcp/connections", "mcp/oauth-clients", "mcp/system-clients",
                    "mcp/service-accounts", "transit", "mcp-credential-broker", Duration.ofSeconds(5)), HttpClient.newHttpClient(),
                    JsonMapper.builder().build(), clock),
            "secret", "mcp/system-clients", "mcp/oauth-clients", clock);

    private DriverManagerDataSource dataSource;

    private DriverManagerDataSource newDatabase() throws SQLException {
        try (Connection admin = DriverManager.getConnection(env.postgres.getJdbcUrl(), env.postgres.getUsername(), env.postgres.getPassword())) {
            admin.createStatement().execute("create database " + database);
        }
        String url = env.postgres.getJdbcUrl().replaceFirst("/[^/?]+(\\?|$)", "/" + database + "$1");
        dataSource = new DriverManagerDataSource(url, env.postgres.getUsername(), env.postgres.getPassword());
        return dataSource;
    }

    private void migrate(String target) {
        Flyway.configure().dataSource(dataSource).locations("classpath:db/migration").target(target).load().migrate();
    }

    private SystemRepository repository() {
        return new SystemRepository(JdbcClient.create(dataSource), JsonMapper.builder().build());
    }

    private LegacySystemImport importer() {
        return new LegacySystemImport(repository(), new ConnectionRepository(JdbcClient.create(dataSource)), secrets,
                new AuditLog("mcp-credential-broker", clock), clock,
                new TransactionTemplate(new DataSourceTransactionManager(dataSource)), IDP_TOKEN_URL);
    }

    private static BrokerProperties.SystemConfig jira() {
        return new BrokerProperties.SystemConfig(URI.create("https://jira.internal"), "atlassian-dc",
                List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, CredentialScheme.BEARER, List.of(),
                Duration.ofSeconds(5), null, null, CredentialScheme.BASIC, null);
    }

    private Map<String, BrokerProperties.SystemConfig> legacy() {
        BrokerProperties.SystemConfig gitlab = new BrokerProperties.SystemConfig(URI.create("https://gitlab.internal"), "gitlab",
                List.of(CredentialType.USER_OAUTH, CredentialType.USER_SECRET), CredentialType.USER_OAUTH, CredentialScheme.BEARER,
                List.of("read_api", "api"), Duration.ofSeconds(3),
                new BrokerProperties.OAuth("mcp-broker", "dev-only-client-secret-" + gitlabId, null, null,
                        URI.create("https://gitlab.internal/oauth/revoke-all")),
                null, null, BrokerProperties.Deployment.DC);
        BrokerProperties.SystemConfig search = new BrokerProperties.SystemConfig(URI.create("https://search.internal"), "opensearch",
                List.of(CredentialType.TOKEN_EXCHANGE), CredentialType.TOKEN_EXCHANGE, CredentialScheme.BEARER, List.of(),
                Duration.ofSeconds(2), null, new BrokerProperties.TokenExchange("mcp-credential-broker", null,
                        URI.create("https://other-idp.internal/token"), "opensearch", List.of("aud-scope")), null, null);
        return Map.of("jira", jira(), gitlabId, gitlab, searchId, search);
    }

    @Test
    void anEmptyTableIsFilledOnceAndTheClientSecretsMoveToThePathOfTheAdminApi(CapturedOutput output) throws Exception {
        env.bao("POST", "secret/data/mcp/oauth-clients/" + searchId, "{\"data\":{\"client_secret\":\"already-in-openbao\"}}");
        newDatabase();
        migrate("7");
        JdbcClient jdbc = JdbcClient.create(dataSource);
        jdbc.sql("insert into connection (sub, system, type, state, backend_user, connected_at, updated_at)"
                + " values ('legacy-sub', 'jira', 'user-secret', 'connected', 'legacy', now(), now())").update();
        migrate("11");
        SystemRepository repository = repository();
        LegacySystemImport importer = importer();

        assertThat(importer.run(legacy())).isEqualTo(3);

        SystemDefinition gitlab = repository.find(gitlabId).orElseThrow();
        assertThat(gitlab.oauth().authorizeUrl()).hasToString("https://gitlab.internal/oauth/authorize");
        assertThat(gitlab.oauth().tokenUrl()).hasToString("https://gitlab.internal/oauth/token");
        assertThat(gitlab.oauth().revokeUrl()).hasToString("https://gitlab.internal/oauth/revoke-all");
        assertThat(gitlab.oauth().scopes()).containsExactly("read_api", "api");
        assertThat(gitlab.timeout()).isEqualTo(Duration.ofSeconds(3));
        assertThat(gitlab.deployment()).isEqualTo(BrokerProperties.Deployment.DC);
        assertThat(gitlab.secretVersion()).isEqualTo(1);
        assertThat(secrets.read(gitlabId, 1).reveal()).isEqualTo("dev-only-client-secret-" + gitlabId);

        SystemDefinition search = repository.find(searchId).orElseThrow();
        assertThat(search.exchangeAudience()).isEqualTo("opensearch");
        assertThat(search.oauth().clientId()).isEqualTo("mcp-credential-broker");
        assertThat(search.oauth().tokenUrl()).as("always the endpoint of the identity provider of the broker").isEqualTo(IDP_TOKEN_URL);
        assertThat(search.oauth().authorizeUrl()).isNull();
        assertThat(search.oauth().scopes()).containsExactly("aud-scope");
        assertThat(search.secretVersion()).as("copied from where 1.x kept it").isEqualTo(1);
        assertThat(secrets.read(searchId, 1).reveal()).isEqualTo("already-in-openbao");

        SystemDefinition jira = repository.find("jira").orElseThrow();
        assertThat(jira.product()).isEqualTo("jira");
        assertThat(jira.oauth()).isNull();
        assertThat(jira.secretVersion()).isNull();
        assertThat(jira.userSecretScheme()).isEqualTo(CredentialScheme.BASIC);
        assertThat(jira.etag()).matches("^[A-Za-z0-9_-]{8,128}$");
        assertThat(new ConnectionRepository(jdbc).find("legacy-sub", "jira")).hasValueSatisfying(
                connection -> assertThat(connection.clientRevision()).as("adopted").isEqualTo(jira.clientRevision()));

        assertThat(AuditLines.all(output)).filteredOn(event -> "system_imported".equals(event.path("reason").stringValue()))
                .extracting(event -> event.path("server").stringValue())
                .containsExactlyInAnyOrder("mcp-jira", "mcp-" + gitlabId, "mcp-" + searchId);
        assertThat(output.getAll()).doesNotContain("dev-only-client-secret-" + gitlabId).doesNotContain("already-in-openbao");

        jdbc.sql("delete from connection").update();
        repository.delete("jira");
        repository.delete(gitlabId);
        repository.delete(searchId);
        assertThat(repository.isEmpty()).isTrue();
        assertThat(importer.run(legacy())).as("not again once it ran, also when every system was deleted").isZero();
        assertThat(repository.isEmpty()).isTrue();
    }

    @Test
    void connectionsOfSystemsThatAreRowsAlreadyGetTheirRevisionFromTheMigration() throws Exception {
        newDatabase();
        migrate("8");
        JdbcClient jdbc = JdbcClient.create(dataSource);
        jdbc.sql("insert into target_system (id, base_url, adapter, product, supported_types, default_type, secret_scheme, etag,"
                + " client_revision, created_at, updated_at) values ('notes', 'https://notes.internal', 'atlassian-dc', 'jira',"
                + " '[\"user-secret\"]', 'user-secret', 'Bearer', 'etag-of-notes', 'revision-of-notes', now(), now())").update();
        jdbc.sql("insert into connection (sub, system, type, state, backend_user, connected_at, updated_at)"
                + " values ('someone', 'notes', 'user-secret', 'connected', 'someone', now(), now())").update();

        migrate("9");

        assertThat(jdbc.sql("select client_revision from connection where sub = 'someone' and system = 'notes'").query(String.class).single())
                .isEqualTo("revision-of-notes");
    }

    @Test
    void theMarkerIsWrittenOnTheFirstStartWhateverThePropertiesSay() throws Exception {
        newDatabase();
        migrate("11");
        SystemRepository repository = repository();

        assertThat(importer().run(Map.of())).isZero();

        assertThat(repository.importDone()).as("no properties at all").isTrue();
        assertThat(importer().run(legacy())).as("properties that show up later are ignored").isZero();
        assertThat(repository.isEmpty()).isTrue();
    }

    @Test
    void aTableThatHasSystemsIsNotTouchedButIsMarked() throws Exception {
        newDatabase();
        migrate("11");
        SystemRepository repository = repository();
        SystemDefinition existing = new SystemDefinition("notes", URI.create("https://notes.internal"), "atlassian-dc", "jira",
                List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, CredentialScheme.BEARER, null, null, null, null, null,
                null, SystemDefinition.newToken(), SystemDefinition.newToken());
        assertThat(repository.insert(existing, clock.instant())).isTrue();

        assertThat(importer().run(legacy())).isZero();

        assertThat(repository.findAll()).extracting(SystemDefinition::id).containsExactly("notes");
        assertThat(repository.importDone()).isTrue();
        repository.delete("notes");
        assertThat(importer().run(legacy())).as("still ignored after the table became empty").isZero();
    }

    @Test
    void twoInstancesStartingTogetherImportOnce() throws Exception {
        newDatabase();
        migrate("11");
        SystemRepository repository = repository();
        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch go = new CountDownLatch(1);
        try {
            List<Future<Integer>> runs = List.of(
                    pool.submit(() -> {
                        go.await();
                        return importer().run(legacy());
                    }),
                    pool.submit(() -> {
                        go.await();
                        return importer().run(legacy());
                    }));
            go.countDown();
            int total = 0;
            for (Future<Integer> run : runs) {
                total += run.get();
            }
            assertThat(total).as("the lock lets one of them import, the other finds the marker").isEqualTo(3);
        } finally {
            pool.shutdownNow();
        }
        assertThat(repository.findAll()).hasSize(3);
        assertThat(repository.importDone()).isTrue();
    }

    @Test
    void aSystemIdThatIsNotOneIsAStartupErrorAndNothingIsStored() throws Exception {
        newDatabase();
        migrate("11");
        SystemRepository repository = repository();
        for (String bad : List.of("Jira", "j", "my-system", "gateway", "x".repeat(32))) {
            assertThatThrownBy(() -> importer().run(Map.of(bad, jira())))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("broker.systems." + bad)
                    .hasMessageContaining("not a valid system id");
        }
        assertThat(repository.isEmpty()).isTrue();
        assertThat(repository.importDone()).as("a failed start leaves no marker").isFalse();
    }

    @Test
    void anAtlassianSystemThatIsNeitherJiraNorConfluenceMustBeCreatedThroughTheApi() throws Exception {
        newDatabase();
        migrate("11");

        assertThatThrownBy(() -> importer().run(Map.of("wiki", jira()))).isInstanceOf(SystemRejectedException.class)
                .hasMessageContaining("product");
        assertThat(repository().isEmpty()).isTrue();
        assertThat(repository().importDone()).as("rolled back with the rest").isFalse();
    }
}
