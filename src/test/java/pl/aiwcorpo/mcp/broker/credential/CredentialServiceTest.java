package pl.aiwcorpo.mcp.broker.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.DataAccessResourceFailureException;

import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.InternalJwtClaims;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.SecretStoreUnavailableException;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import pl.aiwcorpo.mcp.broker.secret.StoredCredential;
import pl.aiwcorpo.mcp.broker.system.BackendIdentity;
import pl.aiwcorpo.mcp.broker.system.SystemAdapter;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry;
import pl.aiwcorpo.mcp.broker.system.WhoamiResult;
import tools.jackson.databind.json.JsonMapper;

class CredentialServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-27T12:00:00Z");
    private static final String RID = "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f";

    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final ConnectionRepository connections = mock(ConnectionRepository.class);
    private final SecretStore secrets = mock(SecretStore.class);
    private final InvalidationPublisher invalidations = mock(InvalidationPublisher.class);
    private final SystemRegistry systems = registry("preferred_username");
    private final CredentialService service = new CredentialService(systems, connections, secrets, invalidations,
            new AuditLog("mcp-credential-broker", clock), clock, 60, Duration.ofDays(7));

    @Test
    void secretStoreOutageFailsClosed() {
        when(connections.find("alice-sub", "jira")).thenReturn(Optional.of(connection(null)));
        when(secrets.get(any())).thenThrow(new SecretStoreUnavailableException("down"));
        assertThatThrownBy(() -> service.resolve(gateway("alice-sub"), "jira", null, null)).isInstanceOf(SecretStoreUnavailableException.class);
        verify(connections, never()).touch(any(), any(), any());
    }

    @Test
    void cacheTtlNeverOutlivesTheCredential() {
        when(connections.find("alice-sub", "jira")).thenReturn(Optional.of(connection(NOW.plusSeconds(10))));
        when(secrets.get(new SecretKey("alice-sub", "jira", "v1")))
                .thenReturn(Optional.of(StoredCredential.of(CredentialType.USER_SECRET, SecretValue.of("alice-pat"))));
        assertThat(service.resolve(gateway("alice-sub"), "jira", null, null).cacheTtlSeconds()).isEqualTo(10);
    }

    @Test
    void expiredConnectionNeedsReconnect() {
        when(connections.find("alice-sub", "jira")).thenReturn(Optional.of(connection(NOW.minusSeconds(1))));
        assertThatThrownBy(() -> service.resolve(gateway("alice-sub"), "jira", null, null)).isInstanceOf(CredentialRequiredException.class);
        verify(secrets, never()).get(any());
    }

    @Test
    void metadataFailureRemovesTheJustStoredSecret() {
        CredentialService withWhoami = serviceWithIdentity(new BackendIdentity("alice", "alice@corp.test"));
        when(connections.find("alice-sub", "jira")).thenReturn(Optional.empty());
        doThrow(new DataAccessResourceFailureException("db down")).when(connections).upsert(any(), any());
        assertThatThrownBy(() -> withWhoami.putSecret(portal("alice-sub", "alice"), "jira", SecretValue.of("alice-pat"), null))
                .isInstanceOf(DataAccessResourceFailureException.class);
        ArgumentCaptor<SecretKey> written = ArgumentCaptor.forClass(SecretKey.class);
        verify(secrets).put(written.capture(), any());
        verify(secrets).delete(written.getValue());
        verify(invalidations, never()).invalidated(any(), any());
    }

    @Test
    void identityComparisonIgnoresAsciiCaseOnly() {
        SystemRegistry.ConfiguredSystem byName = registry("preferred_username").find("jira").orElseThrow();
        assertThat(CredentialService.sameIdentity(portal("s", "Alice", true), byName, new BackendIdentity("alice", null))).isTrue();
        assertThat(CredentialService.sameIdentity(portal("s", "Alice", true), byName, new BackendIdentity("alice2", null))).isFalse();
        assertThat(CredentialService.sameName("\u0141ukasz", "\u0141ukasz")).isTrue();
        assertThat(CredentialService.sameName("\u0141UKASZ", "\u0142ukasz")).isFalse();
        assertThat(CredentialService.sameName("\u212Aate", "kate")).as("KELVIN SIGN folds to k").isFalse();
    }

    @Test
    void emailIdentityNeedsAVerifiedEmail() {
        SystemRegistry.ConfiguredSystem byEmail = registry("email").find("jira").orElseThrow();
        BackendIdentity backend = new BackendIdentity("x", "ALICE@corp.test");
        assertThat(CredentialService.sameIdentity(portal("s", "alice", true), byEmail, backend)).isTrue();
        assertThat(CredentialService.sameIdentity(portal("s", "alice", false), byEmail, backend)).isFalse();
        assertThat(CredentialService.sameIdentity(portal("s", "alice", null), byEmail, backend)).isFalse();
        assertThat(CredentialService.sameIdentity(portal("s", "alice", true), byEmail, new BackendIdentity("alice", null)))
                .isFalse();
    }

    @Test
    void subjectTokenIsRefusedForUserSecretSystems() {
        assertThatThrownBy(() -> service.resolve(gateway("alice-sub"), "jira", null, "exchanged-token"))
                .isInstanceOf(InvalidRequestException.class);
        assertThatThrownBy(() -> service.resolve(gateway("alice-sub"), "jira", List.of("a", "a"), null))
                .isInstanceOf(InvalidRequestException.class);
        verify(connections, never()).find(any(), any());
    }

    @Test
    void lastUsedIsWrittenAtMostEveryFewMinutes() {
        StoredCredential pat = StoredCredential.of(CredentialType.USER_SECRET, SecretValue.of("alice-pat"));
        when(secrets.get(any())).thenReturn(Optional.of(pat));
        when(connections.find("alice-sub", "jira")).thenReturn(Optional.of(connection(null, NOW.minusSeconds(60))));
        service.resolve(gateway("alice-sub"), "jira", null, null);
        verify(connections, never()).touch(any(), any(), any());
        when(connections.find("alice-sub", "jira")).thenReturn(Optional.of(connection(null, NOW.minusSeconds(600))));
        service.resolve(gateway("alice-sub"), "jira", null, null);
        verify(connections).touch("alice-sub", "jira", NOW);
    }

    @Test
    void replacingRemovesThePreviousValueAfterTheSwitch() {
        CredentialService withWhoami = serviceWithIdentity(new BackendIdentity("alice", "alice@corp.test"));
        when(connections.find("alice-sub", "jira")).thenReturn(Optional.of(connection(null)));
        withWhoami.putSecret(portal("alice-sub", "alice", true), "jira", SecretValue.of("alice-pat"), null);
        ArgumentCaptor<SecretKey> written = ArgumentCaptor.forClass(SecretKey.class);
        verify(secrets).put(written.capture(), any());
        assertThat(written.getValue().version()).isNotEqualTo("v1");
        verify(secrets).delete(new SecretKey("alice-sub", "jira", "v1"));
        verify(secrets, never()).delete(written.getValue());
        verify(invalidations).invalidated("alice-sub", "jira");
    }

    @Test
    void secretValueNeverPrints() {
        SecretValue secret = SecretValue.of("alice-pat");
        assertThat(secret.toString()).doesNotContain("alice-pat");
        assertThat(StoredCredential.of(CredentialType.USER_SECRET, secret).toString()).doesNotContain("alice-pat");
        assertThat(new CredentialService.Resolved(CredentialScheme.BEARER, secret, CredentialType.USER_SECRET, null, 60)
                .toString()).doesNotContain("alice-pat");
    }

    private CredentialService serviceWithIdentity(BackendIdentity identity) {
        SystemRegistry registry = mock(SystemRegistry.class);
        SystemAdapter adapter = (scheme, secret) ->
                new WhoamiResult.Identified(identity);
        when(registry.find("jira")).thenReturn(Optional.of(
                new SystemRegistry.ConfiguredSystem("jira", config("preferred_username"), adapter)));
        return new CredentialService(registry, connections, secrets, invalidations,
                new AuditLog("mcp-credential-broker", clock), clock, 60, Duration.ofDays(7));
    }

    private static SystemRegistry registry(String identityClaim) {
        return new SystemRegistry(Map.of("jira", config(identityClaim)), HttpClient.newHttpClient(), JsonMapper.builder().build());
    }

    private static BrokerProperties.SystemConfig config(String identityClaim) {
        return new BrokerProperties.SystemConfig(URI.create("http://jira.test"), "atlassian-dc",
                List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, CredentialScheme.BEARER, identityClaim,
                List.of(), Duration.ofSeconds(1));
    }

    private static Connection connection(Instant expiresAt) {
        return connection(expiresAt, null);
    }

    private static Connection connection(Instant expiresAt, Instant lastUsedAt) {
        return new Connection("alice-sub", "jira", CredentialType.USER_SECRET, Connection.StoredState.CONNECTED, "alice",
                expiresAt, NOW.minusSeconds(3600), lastUsedAt, "v1");
    }

    private static Caller.Gateway gateway(String sub) {
        return new Caller.Gateway(RID, new InternalJwtClaims(sub, "alice", List.of(), "claude-code", "get_issue", null,
                RID, "20261026120000-a1b2c3d", "jti-1", false));
    }

    private static Caller.PortalUser portal(String sub, String username) {
        return portal(sub, username, true);
    }

    private static Caller.PortalUser portal(String sub, String username, Boolean emailVerified) {
        Map<String, Object> claims = new HashMap<>(Map.of("sub", sub, "preferred_username", username,
                "email", username.toLowerCase(Locale.ROOT) + "@corp.test"));
        if (emailVerified != null) {
            claims.put("email_verified", emailVerified);
        }
        return new Caller.PortalUser(RID, sub, username, "mcp-portal-bff", claims);
    }
}
