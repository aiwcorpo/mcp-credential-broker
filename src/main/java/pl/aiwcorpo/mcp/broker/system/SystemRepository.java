package pl.aiwcorpo.mcp.broker.system;

import java.net.URI;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;

import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Rows of {@code target_system}; the one source of the systems of every broker instance. */
public class SystemRepository {

    private static final String COLUMNS = """
            id, base_url, adapter, product, supported_types, default_type, secret_scheme, oauth_client_id, oauth_authorize_url,
            oauth_token_url, oauth_revoke_url, oauth_scopes, secret_version, exchange_audience, user_secret_scheme,
            deployment, timeout_ms, etag, client_revision, display_name, whoami_path, whoami_username_field
            """;

    private final JdbcClient jdbc;
    private final JsonMapper json;

    public SystemRepository(JdbcClient jdbc, JsonMapper json) {
        this.jdbc = jdbc;
        this.json = json;
    }

    public List<SystemDefinition> findAll() {
        return jdbc.sql("select " + COLUMNS + " from target_system order by id").query(this::map).list();
    }

    public Optional<SystemDefinition> find(String id) {
        return jdbc.sql("select " + COLUMNS + " from target_system where id = :id").param("id", id).query(this::map).optional();
    }

    /** @return false when a system with this id exists */
    public boolean insert(SystemDefinition system, Instant now) {
        return write("""
                insert into target_system (id, base_url, adapter, product, supported_types, default_type, secret_scheme,
                    oauth_client_id, oauth_authorize_url, oauth_token_url, oauth_revoke_url, oauth_scopes, secret_version,
                    exchange_audience, user_secret_scheme, deployment, timeout_ms, etag, client_revision, display_name, whoami_path, whoami_username_field, created_at, updated_at)
                values (:id, :baseUrl, :adapter, :product, cast(:types as jsonb), :defaultType, :secretScheme, :clientId,
                    :authorizeUrl, :tokenUrl, :revokeUrl, cast(:scopes as jsonb), :secretVersion, :audience, :userScheme,
                    :deployment, :timeoutMs, :etag, :revision, :displayName, :whoamiPath, :whoamiField, :now, :now)
                on conflict (id) do nothing
                """, system, now, null) == 1;
    }

    /** @return false when the row is gone or its etag is no longer {@code expectedEtag} */
    public boolean update(SystemDefinition system, String expectedEtag, Instant now) {
        return write("""
                update target_system set base_url = :baseUrl, adapter = :adapter, product = :product,
                    supported_types = cast(:types as jsonb),
                    default_type = :defaultType, secret_scheme = :secretScheme, oauth_client_id = :clientId,
                    oauth_authorize_url = :authorizeUrl, oauth_token_url = :tokenUrl, oauth_revoke_url = :revokeUrl,
                    oauth_scopes = cast(:scopes as jsonb), secret_version = :secretVersion, exchange_audience = :audience,
                    user_secret_scheme = :userScheme, deployment = :deployment, timeout_ms = :timeoutMs, etag = :etag,
                    client_revision = :revision, display_name = :displayName, whoami_path = :whoamiPath,
                    whoami_username_field = :whoamiField, updated_at = :now
                where id = :id and etag = :expected
                """, system, now, expectedEtag) == 1;
    }

    public boolean delete(String id) {
        return jdbc.sql("delete from target_system where id = :id").param("id", id).update() == 1;
    }

    /** @return false when the row is gone or changed since {@code etag} */
    public boolean delete(String id, String etag) {
        return jdbc.sql("delete from target_system where id = :id and etag = :etag").param("id", id).param("etag", etag).update() == 1;
    }

    /** Serializes the import of 1.x properties between instances that start together; released at the end of the transaction. */
    public void lockForImport() {
        jdbc.sql("select pg_advisory_xact_lock(7311002)").query().singleRow();
    }

    public boolean importDone() {
        return jdbc.sql("select count(*) from target_system_import").query(Long.class).single() > 0;
    }

    public boolean isEmpty() {
        return jdbc.sql("select count(*) from target_system").query(Long.class).single() == 0;
    }

    public void markImported(Instant now) {
        jdbc.sql("insert into target_system_import (imported_at) values (:now) on conflict do nothing")
                .param("now", Timestamp.from(now)).update();
    }

    private int write(String sql, SystemDefinition system, Instant now, String expectedEtag) {
        SystemDefinition.Oauth oauth = system.oauth();
        JdbcClient.StatementSpec statement = jdbc.sql(sql)
                .param("id", system.id())
                .param("baseUrl", system.baseUrl().toString())
                .param("adapter", system.adapter())
                .param("product", system.product())
                .param("types", json.writeValueAsString(system.supportedTypes().stream().map(CredentialType::wire).toList()))
                .param("defaultType", system.defaultType().wire())
                .param("secretScheme", system.secretScheme().wire())
                .param("clientId", oauth == null ? null : oauth.clientId())
                .param("authorizeUrl", oauth == null || oauth.authorizeUrl() == null ? null : oauth.authorizeUrl().toString())
                .param("tokenUrl", oauth == null ? null : oauth.tokenUrl().toString())
                .param("revokeUrl", oauth == null || oauth.revokeUrl() == null ? null : oauth.revokeUrl().toString())
                .param("scopes", json.writeValueAsString(oauth == null ? List.of() : oauth.scopes()))
                .param("secretVersion", system.secretVersion())
                .param("audience", system.exchangeAudience())
                .param("userScheme", system.userSecretScheme() == null ? null : system.userSecretScheme().wire())
                .param("deployment", system.deployment() == null ? null : system.deployment().wire())
                .param("timeoutMs", system.timeout() == null ? null : (int) system.timeout().toMillis())
                .param("etag", system.etag())
                .param("revision", system.clientRevision())
                .param("displayName", system.displayName())
                .param("whoamiPath", system.whoami() == null ? null : system.whoami().path())
                .param("whoamiField", system.whoami() == null ? null : system.whoami().usernameField())
                .param("now", Timestamp.from(now));
        if (expectedEtag != null) {
            statement = statement.param("expected", expectedEtag);
        }
        return statement.update();
    }

    private SystemDefinition map(ResultSet rs, int row) throws SQLException {
        List<CredentialType> types = new ArrayList<>();
        for (JsonNode type : json.readTree(rs.getString("supported_types"))) {
            types.add(CredentialType.fromWire(type.asString("")).orElseThrow(() -> new SQLException("unknown credential type in row")));
        }
        List<String> scopes = new ArrayList<>();
        json.readTree(rs.getString("oauth_scopes")).forEach(scope -> scopes.add(scope.asString("")));
        String clientId = rs.getString("oauth_client_id");
        SystemDefinition.Oauth oauth = clientId == null ? null : new SystemDefinition.Oauth(clientId,
                uri(rs.getString("oauth_authorize_url")), uri(rs.getString("oauth_token_url")),
                uri(rs.getString("oauth_revoke_url")), scopes);
        int timeoutMs = rs.getInt("timeout_ms");
        boolean noTimeout = rs.wasNull();
        int version = rs.getInt("secret_version");
        boolean noVersion = rs.wasNull();
        return new SystemDefinition(rs.getString("id"), URI.create(rs.getString("base_url")), rs.getString("adapter"),
                rs.getString("product"), types,
                CredentialType.fromWire(rs.getString("default_type")).orElseThrow(() -> new SQLException("unknown default type")),
                scheme(rs.getString("secret_scheme")), oauth, noVersion ? null : version,
                noTimeout ? null : Duration.ofMillis(timeoutMs), rs.getString("exchange_audience"),
                rs.getString("user_secret_scheme") == null ? null : scheme(rs.getString("user_secret_scheme")),
                deployment(rs.getString("deployment")), rs.getString("etag"), rs.getString("client_revision"), rs.getString("display_name"),
                rs.getString("whoami_path") == null ? null
                        : new SystemDefinition.Whoami(rs.getString("whoami_path"), rs.getString("whoami_username_field")));
    }

    private static URI uri(String value) {
        return value == null ? null : URI.create(value);
    }

    private static CredentialScheme scheme(String wire) throws SQLException {
        for (CredentialScheme scheme : CredentialScheme.values()) {
            if (scheme.wire().equals(wire)) {
                return scheme;
            }
        }
        throw new SQLException("unknown credential scheme in row");
    }

    private static BrokerProperties.Deployment deployment(String wire) {
        for (BrokerProperties.Deployment deployment : BrokerProperties.Deployment.values()) {
            if (deployment.wire().equals(wire)) {
                return deployment;
            }
        }
        return null;
    }
}
