package pl.aiwcorpo.mcp.broker.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.core.io.Resource;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import pl.aiwcorpo.mcp.broker.audit.AuditLog;
import pl.aiwcorpo.mcp.broker.auth.Caller;
import pl.aiwcorpo.mcp.broker.auth.InternalJwtClaims;
import pl.aiwcorpo.mcp.broker.auth.InternalJwtVerifier.ToolClaim;
import pl.aiwcorpo.mcp.broker.auth.Operation;
import pl.aiwcorpo.mcp.broker.auth.SubjectTokenVerifier;
import pl.aiwcorpo.mcp.broker.auth.TestGatewayVerifier;
import pl.aiwcorpo.mcp.broker.auth.TokenRejectedException;
import pl.aiwcorpo.mcp.broker.config.BrokerProperties;
import pl.aiwcorpo.mcp.broker.event.InvalidationPublisher;
import pl.aiwcorpo.mcp.broker.oauth.RateLimiter;
import pl.aiwcorpo.mcp.broker.secret.SecretKey;
import pl.aiwcorpo.mcp.broker.secret.SecretStore;
import pl.aiwcorpo.mcp.broker.secret.SecretValue;
import pl.aiwcorpo.mcp.broker.secret.ServiceAccountKeys;
import pl.aiwcorpo.mcp.broker.secret.StoredCredential;
import pl.aiwcorpo.mcp.broker.support.AuditLines;
import pl.aiwcorpo.mcp.broker.support.Contracts;
import pl.aiwcorpo.mcp.broker.support.TestTokens;
import pl.aiwcorpo.mcp.broker.system.ServiceAccountSource;
import pl.aiwcorpo.mcp.broker.system.SystemDefinition;
import pl.aiwcorpo.mcp.broker.system.SystemRejectedException;
import pl.aiwcorpo.mcp.broker.system.SystemRules;
import pl.aiwcorpo.mcp.broker.system.SystemRegistry;
import pl.aiwcorpo.mcp.broker.system.TokenExchanger;
import tools.jackson.databind.JsonNode;

/**
 * Who may be handed which credential (CC-261): the decision of resolve for a token with {@code pty}, and that an agent that is
 * refused never reaches the connection table, the secret store or the IdP. The vectors are test-vectors/broker-eligibility.
 */
@ExtendWith(OutputCaptureExtension.class)
class AgentEligibilityTest {

    private static final Instant NOW = Instant.parse("2026-10-27T12:00:00Z");
    private static final String RID = "0192d1b2-7c3a-7d4e-8f10-2a3b4c5d6e7f";
    private static final String SYSTEM = "desk";

    /** Vectors about the admin write: the 422 rule is replayed here, the MFA rules by SystemAdminIntegrationTest. */
    private static final List<String> ADMIN_VECTORS = List.of("agents-allowed-disabled-alone-no-mfa.json",
            "agents-allowed-enabled-needs-fresh-mfa.json", "agents-allowed-without-service-account-422.json");

    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final ConnectionRepository connections = mock(ConnectionRepository.class);
    private final SecretStore secrets = mock(SecretStore.class);
    private final SubjectTokenVerifier subjectTokens = mock(SubjectTokenVerifier.class);
    private final ServiceAccountSource sharedKey = mock(ServiceAccountSource.class);
    private final TokenExchanger exchanger = mock(TokenExchanger.class);

    static Stream<Arguments> vectors() {
        List<Resource> files = Contracts.vectors("broker-eligibility");
        assertThat(files).hasSizeGreaterThanOrEqualTo(15);
        return files.stream().map(file -> Arguments.of(file.getFilename(), Contracts.JSON.readTree(read(file))));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void vector(String name, JsonNode vector) {
        JsonNode input = vector.path("input");
        JsonNode expected = vector.path("expected");
        if (!input.has("operation")) {
            assertThat(ADMIN_VECTORS).as("a vector without an operation must be known and replayed elsewhere").contains(name);
            replayAdminVector(name, input, expected);
            return;
        }
        Map<String, Object> claims = claimsOf(input.path("claims"));
        int status = expected.path("status").asInt();
        if (status == 401) {
            assertThat(reasonOfToken(claims)).as(name).isEqualTo(expected.path("error").stringValue());
            return;
        }
        JsonNode system = input.path("system");
        InternalJwtClaims verified = verified(claims);

        if ("authenticator".equals(input.path("operation").stringValue())) {
            String refusal = Operation.GET_AUTHENTICATOR.refusalForPrincipal(verified.pty());
            assertThat(refusal).as(name).isEqualTo(status == 403 ? expected.path("error").stringValue() : null);
            return;
        }
        // The vectors list the types a system could have; a real system takes token-exchange and service-account alone
        // (credential_types_mixed), so the system here is the one of the credentialType the vector resolves.
        CredentialType type = CredentialType.fromWire(input.path("credentialType").stringValue()).orElseThrow();
        CredentialService service = service(system(List.of(type), type, system.path("agentsAllowed").booleanValue()));
        String subjectToken = type == CredentialType.TOKEN_EXCHANGE ? "subject-token" : null;
        when(sharedKey.key()).thenReturn(new ServiceAccountKeys.Key(SecretValue.of("shared-key"), null));
        when(exchanger.exchange(any())).thenReturn(new TokenExchanger.ExchangedToken(SecretValue.of("exchanged"), NOW.plusSeconds(300)));
        when(connections.find(verified.sub(), SYSTEM)).thenReturn(Optional.of(connection(verified.sub())));
        when(secrets.get(new SecretKey(verified.sub(), SYSTEM, "v1")))
                .thenReturn(Optional.of(StoredCredential.of(CredentialType.USER_SECRET, SecretValue.of("user-secret-value"))));

        if (status == 403) {
            assertThatThrownBy(() -> service.resolve(new Caller.Gateway(RID, verified), SYSTEM, null, subjectToken))
                    .as(name).isInstanceOf(PrincipalNotEligibleException.class);
            assertThat(expected.path("touchedStore").booleanValue()).isFalse();
            verifyNothingTouched();
        } else {
            assertThat(service.resolve(new Caller.Gateway(RID, verified), SYSTEM, null, subjectToken).type()).as(name).isEqualTo(type);
        }
    }

    private static void replayAdminVector(String name, JsonNode input, JsonNode expected) {
        if (expected.path("status").asInt() != 422) {
            return;
        }
        List<CredentialType> types = new java.util.ArrayList<>();
        input.path("after").path("supportedTypes").forEach(type -> types.add(CredentialType.fromWire(type.stringValue()).orElseThrow()));
        SystemDefinition definition = new SystemDefinition("desk", URI.create("https://desk.test"), "generic-rest", null, types,
                types.get(0), CredentialScheme.BEARER, null, null, null, null, null, null, "etag-etag-etag", "revision-revision")
                .withAgentsAllowed(input.path("after").path("agentsAllowed").booleanValue());
        assertThatThrownBy(() -> SystemRules.checkAgentsFlag(definition)).as(name)
                .isInstanceOfSatisfying(SystemRejectedException.class,
                        e -> assertThat(e.reason()).isEqualTo(expected.path("reason").stringValue()));
    }

    @Test
    void anAgentIsRefusedAUserSecretBeforeTheConnectionTableOrTheSecretStoreIsTouched() {
        CredentialService service = service(system(List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, false));

        assertThatThrownBy(() -> service.resolve(agent(), SYSTEM, null, null)).isInstanceOf(PrincipalNotEligibleException.class);

        verifyNothingTouched();
    }

    @Test
    void anAgentIsRefusedUserOauthBeforeTheConnectionTableOrTheSecretStoreIsTouched() {
        CredentialService service = service(system(List.of(CredentialType.USER_OAUTH), CredentialType.USER_OAUTH, false));

        assertThatThrownBy(() -> service.resolve(agent(), SYSTEM, null, null)).isInstanceOf(PrincipalNotEligibleException.class);

        verifyNothingTouched();
    }

    @Test
    void anAgentIsRefusedTheSharedKeyOfASystemThatDoesNotAllowAgents() {
        CredentialService service = service(system(List.of(CredentialType.SERVICE_ACCOUNT), CredentialType.SERVICE_ACCOUNT, false));

        assertThatThrownBy(() -> service.resolve(agent(), SYSTEM, null, null)).isInstanceOf(PrincipalNotEligibleException.class);

        verifyNothingTouched();
    }

    @Test
    void anAgentGetsTheSharedKeyOfASystemThatAllowsAgents() {
        when(sharedKey.key()).thenReturn(new ServiceAccountKeys.Key(SecretValue.of("shared-key"), null));
        CredentialService service = service(system(List.of(CredentialType.SERVICE_ACCOUNT), CredentialType.SERVICE_ACCOUNT, true));

        assertThat(service.resolve(agent(), SYSTEM, null, null).value().reveal()).isEqualTo("shared-key");
    }

    @Test
    void anAgentGetsATokenExchangedForItsOwnSub() {
        when(exchanger.exchange(any())).thenReturn(new TokenExchanger.ExchangedToken(SecretValue.of("exchanged"), NOW.plusSeconds(300)));
        CredentialService service = service(system(List.of(CredentialType.TOKEN_EXCHANGE), CredentialType.TOKEN_EXCHANGE, false));

        assertThat(service.resolve(agent(), SYSTEM, null, "agent-subject-token").type()).isEqualTo(CredentialType.TOKEN_EXCHANGE);

        verify(subjectTokens).verify("agent-subject-token", "agent-sub");
        verifyNoInteractions(connections, secrets);
    }

    @Test
    void aDelegatedCallResolvesTheUserSecretOfTheHumanSub() {
        when(connections.find("human-sub", SYSTEM)).thenReturn(Optional.of(connection("human-sub")));
        when(secrets.get(new SecretKey("human-sub", SYSTEM, "v1")))
                .thenReturn(Optional.of(StoredCredential.of(CredentialType.USER_SECRET, SecretValue.of("human-pat"))));
        CredentialService service = service(system(List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, false));

        InternalJwtClaims delegated = new InternalJwtClaims("human-sub", "alice", List.of(), "claude-code", "get_issue", RID, 7L, "jti-d",
                false, null, "delegated", new InternalJwtClaims.Actor("agent-sub", "agent-triage"));

        assertThat(service.resolve(new Caller.Gateway(RID, delegated), SYSTEM, null, null).value().reveal()).isEqualTo("human-pat");
    }

    @Test
    void aRefusedAgentIsAuditedAsAnAgentWithoutAnyTokenValue(CapturedOutput output) {
        CredentialService service = service(system(List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, false));

        assertThatThrownBy(() -> service.resolve(agent(), SYSTEM, null, null)).isInstanceOf(PrincipalNotEligibleException.class);

        assertThat(AuditLines.of(output, RID)).singleElement().satisfies(event -> {
            assertThat(event.path("event").stringValue()).isEqualTo("credential_resolve");
            assertThat(event.path("outcome").stringValue()).isEqualTo("denied");
            assertThat(event.path("reason").stringValue()).isEqualTo("principal_not_eligible");
            assertThat(event.path("principalType").stringValue()).isEqualTo("agent");
            assertThat(event.path("credentialType").stringValue()).isEqualTo("user-secret");
            assertThat(event.has("actorSub")).isFalse();
        });
    }

    @Test
    void aDelegatedCallIsAuditedWithTheHumanAsSubAndTheAgentAsActor(CapturedOutput output) {
        when(connections.find("human-sub", SYSTEM)).thenReturn(Optional.empty());
        CredentialService service = service(system(List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, false));
        InternalJwtClaims delegated = new InternalJwtClaims("human-sub", "alice", List.of(), "claude-code", "get_issue", RID, 7L, "jti-d",
                false, null, "delegated", new InternalJwtClaims.Actor("agent-sub", "agent-triage"));

        assertThatThrownBy(() -> service.resolve(new Caller.Gateway(RID, delegated), SYSTEM, null, null))
                .isInstanceOf(CredentialRequiredException.class);

        assertThat(AuditLines.of(output, RID)).singleElement().satisfies(event -> {
            assertThat(event.path("sub").stringValue()).isEqualTo("human-sub");
            assertThat(event.path("principalType").stringValue()).isEqualTo("delegated");
            assertThat(event.path("actorSub").stringValue()).isEqualTo("agent-sub");
            assertThat(event.path("actorClient").stringValue()).isEqualTo("agent-triage");
        });
    }

    @Test
    void aHumanIsNeverWrittenWithAPrincipalType(CapturedOutput output) {
        when(connections.find("human-sub", SYSTEM)).thenReturn(Optional.empty());
        CredentialService service = service(system(List.of(CredentialType.USER_SECRET), CredentialType.USER_SECRET, false));
        InternalJwtClaims human = new InternalJwtClaims("human-sub", "alice", List.of(), "claude-code", "get_issue", RID, 7L, "jti-h", false);

        assertThatThrownBy(() -> service.resolve(new Caller.Gateway(RID, human), SYSTEM, null, null))
                .isInstanceOf(CredentialRequiredException.class);

        assertThat(AuditLines.of(output, RID)).singleElement().satisfies(event -> {
            assertThat(event.has("principalType")).isFalse();
            assertThat(event.has("actorSub")).isFalse();
        });
    }

    @Test
    void theAuthenticatorCallsRefuseAnAgentAndServeADelegatedCall() {
        for (Operation operation : List.of(Operation.GET_AUTHENTICATOR, Operation.VERIFY_CODE, Operation.INVALIDATE_CODES)) {
            assertThat(operation.refusalForPrincipal("agent")).as(operation.operationId()).isEqualTo("principal_not_eligible");
            assertThat(operation.refusalForPrincipal("delegated")).as(operation.operationId()).isNull();
            assertThat(operation.refusalForPrincipal(null)).as(operation.operationId()).isNull();
        }
    }

    @Test
    void everyOperationButResolveAndTheAuthenticatorCallsRefusesATokenWithPty() {
        List<Operation> served = List.of(Operation.RESOLVE, Operation.GET_AUTHENTICATOR, Operation.VERIFY_CODE, Operation.INVALIDATE_CODES);
        for (Operation operation : Operation.ALL) {
            if (served.contains(operation)) {
                continue;
            }
            assertThat(operation.refusalForPrincipal("agent")).as(operation.operationId()).isEqualTo("forbidden");
            assertThat(operation.refusalForPrincipal("delegated")).as(operation.operationId()).isEqualTo("forbidden");
        }
        assertThat(Operation.RESOLVE.refusalForPrincipal("agent")).isNull();
        assertThat(Operation.RESOLVE.refusalForPrincipal("delegated")).isNull();
    }

    private void verifyNothingTouched() {
        verifyNoInteractions(connections, secrets, subjectTokens, exchanger, sharedKey);
    }

    private CredentialService service(SystemRegistry.ConfiguredSystem system) {
        SystemRegistry registry = mock(SystemRegistry.class);
        when(registry.find(SYSTEM)).thenReturn(Optional.of(system));
        return new CredentialService(registry, connections, secrets, mock(InvalidationPublisher.class), mock(pl.aiwcorpo.mcp.broker.credential.OAuthService.class),
                subjectTokens, new AuditLog("mcp-credential-broker", clock), clock, 60, Duration.ofDays(7),
                new LostSecretSignal(clock, new SimpleMeterRegistry()), mock(RateLimiter.class), 10);
    }

    private SystemRegistry.ConfiguredSystem system(List<CredentialType> types, CredentialType defaultType, boolean agentsAllowed) {
        BrokerProperties.SystemConfig config = new BrokerProperties.SystemConfig(URI.create("http://desk.test"), "generic-rest", types,
                defaultType, CredentialScheme.BEARER, List.of(), Duration.ofSeconds(1), null, null, null, null);
        return new SystemRegistry.ConfiguredSystem(SYSTEM, config, null, exchanger, sharedKey, "etag-desk", "revision-desk", null,
                agentsAllowed);
    }

    private static Connection connection(String sub) {
        return new Connection(sub, SYSTEM, CredentialType.USER_SECRET, Connection.StoredState.CONNECTED, "alice", null,
                NOW.minusSeconds(3600), null, "v1", null, "revision-desk");
    }

    private static Caller.Gateway agent() {
        return new Caller.Gateway(RID, new InternalJwtClaims("agent-sub", "service-account-agent-triage", List.of(), "agent-triage",
                "get_issue", RID, 7L, "jti-a", false, null, "agent", null));
    }

    private static Map<String, Object> claimsOf(JsonNode claims) {
        Map<String, Object> map = new LinkedHashMap<>();
        claims.propertyNames().forEach(name -> map.put(name, toJava(claims.path(name))));
        if (map.get("act") instanceof Map<?, ?> act && !act.containsKey("azp")) {
            // The vectors abbreviate act to its sub; the schema wants both.
            Map<String, Object> full = new LinkedHashMap<>();
            act.forEach((key, value) -> full.put((String) key, value));
            full.put("azp", "agent-test");
            map.put("act", full);
        }
        return map;
    }

    private static Object toJava(JsonNode node) {
        if (node.isObject()) {
            Map<String, Object> map = new LinkedHashMap<>();
            node.propertyNames().forEach(name -> map.put(name, toJava(node.path(name))));
            return map;
        }
        return node.stringValue();
    }

    private static String tokenOf(Map<String, Object> claims) {
        Map<String, Object> extra = new LinkedHashMap<>(claims);
        extra.putIfAbsent("tool", null);
        return new TestTokens().gatewayUserWithClaims("subject-sub", "alice", RID, extra);
    }

    private static InternalJwtClaims verified(Map<String, Object> claims) {
        return TestGatewayVerifier.create().verify(tokenOf(claims), RID, false, ToolClaim.TOOL_OR_RESOURCE);
    }

    private static String reasonOfToken(Map<String, Object> claims) {
        try {
            TestGatewayVerifier.create().verify(tokenOf(claims), RID, false, ToolClaim.TOOL_OR_RESOURCE);
            return null;
        } catch (TokenRejectedException e) {
            return e.reason();
        }
    }

    private static byte[] read(Resource file) {
        try {
            return file.getContentAsByteArray();
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }
}
