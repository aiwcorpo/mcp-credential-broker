package pl.aiwcorpo.mcp.broker.system;

import java.util.List;
import java.util.Set;

import pl.aiwcorpo.mcp.broker.credential.CredentialScheme;
import pl.aiwcorpo.mcp.broker.credential.CredentialType;

/** What a stored system must satisfy; the same checks the 1.x start-up made, now answered as 422 system_rejected. */
public final class SystemRules {

    public static final Set<String> ADAPTERS = Set.of("atlassian-dc", "gitlab", "opensearch", "generic-rest");

    private static final Set<CredentialType> USER_TYPES = Set.of(CredentialType.USER_SECRET, CredentialType.USER_OAUTH);
    private static final Set<String> USER_ADAPTERS = Set.of("gitlab", "atlassian-dc");
    private static final Set<String> PRODUCTS = Set.of("jira", "confluence");
    private static final Set<String> OAUTH_ADAPTERS = Set.of("gitlab");

    private SystemRules() {
    }

    public static void check(SystemDefinition system) {
        if (SystemIds.isReserved(system.id())) {
            throw new SystemRejectedException("system_reserved", "the system id is reserved");
        }
        List<CredentialType> types = system.supportedTypes();
        if (!types.contains(system.defaultType())) {
            throw new SystemRejectedException("default_type_not_supported", "defaultType must be one of supportedTypes");
        }
        for (CredentialType single : List.of(CredentialType.TOKEN_EXCHANGE, CredentialType.SERVICE_ACCOUNT)) {
            if (types.contains(single) && types.size() != 1) {
                throw new SystemRejectedException("credential_types_mixed", single.wire() + " cannot be combined with other types");
            }
        }
        boolean userTypes = types.stream().anyMatch(USER_TYPES::contains);
        String adapter = system.adapter();
        if ("generic-rest".equals(adapter) && types.contains(CredentialType.USER_OAUTH)) {
            throw new SystemRejectedException("credential_type_not_supported_by_adapter",
                    "the adapter generic-rest takes user-secret or service-account, not user-oauth");
        }
        if (userTypes && !USER_ADAPTERS.contains(adapter) && !"generic-rest".equals(adapter)) {
            throw new SystemRejectedException("adapter_type_mismatch", "adapter " + adapter + " has no user credentials");
        }
        if (types.equals(List.of(CredentialType.TOKEN_EXCHANGE)) && !"opensearch".equals(adapter)) {
            throw new SystemRejectedException("adapter_type_mismatch", "token-exchange needs the adapter opensearch");
        }
        if (system.whoami() != null && (!"generic-rest".equals(adapter) || !types.contains(CredentialType.USER_SECRET))) {
            throw new SystemRejectedException("whoami_not_applicable", "whoami belongs to a generic-rest system with user-secret");
        }
        if (types.equals(List.of(CredentialType.SERVICE_ACCOUNT)) && !"generic-rest".equals(adapter)) {
            throw new SystemRejectedException("adapter_type_mismatch", "service-account needs the adapter generic-rest");
        }
        if (types.contains(CredentialType.USER_OAUTH) && !OAUTH_ADAPTERS.contains(adapter)) {
            throw new SystemRejectedException("adapter_type_mismatch", "adapter " + adapter + " does not speak OAuth");
        }
        if ((types.contains(CredentialType.USER_OAUTH) || types.contains(CredentialType.TOKEN_EXCHANGE)) && system.oauth() == null) {
            throw new SystemRejectedException("oauth_required", types.contains(CredentialType.USER_OAUTH)
                    ? "user-oauth needs an oauth client" : "token-exchange needs the client of the identity provider in oauth");
        }
        if ("atlassian-dc".equals(adapter) ? system.product() == null || !PRODUCTS.contains(system.product()) : system.product() != null) {
            throw new SystemRejectedException("product_required", "atlassian-dc needs product jira or confluence, other adapters take none");
        }
        boolean exchange = types.contains(CredentialType.TOKEN_EXCHANGE);
        if (exchange ? system.exchangeAudience() == null || system.exchangeAudience().isBlank() : system.exchangeAudience() != null) {
            throw new SystemRejectedException("exchange_audience_required",
                    "exchangeAudience is required for token-exchange and not allowed otherwise");
        }
        if (types.contains(CredentialType.USER_OAUTH) && (system.oauth().authorizeUrl() == null || system.oauth().tokenUrl() == null)) {
            throw new SystemRejectedException("oauth_required", "user-oauth needs authorizeUrl and tokenUrl");
        }
        CredentialScheme userScheme = system.userSecretScheme();
        if (userScheme != null && ((userScheme != CredentialScheme.BEARER && userScheme != CredentialScheme.BASIC)
                || !types.contains(CredentialType.USER_SECRET))) {
            throw new SystemRejectedException("secret_scheme_not_supported",
                    "userSecretScheme is Bearer or Basic and only for a system with user-secret");
        }
        if (types.contains(CredentialType.USER_SECRET) && userScheme == null && system.secretScheme() != CredentialScheme.BEARER
                && system.secretScheme() != CredentialScheme.BASIC) {
            throw new SystemRejectedException("secret_scheme_not_supported", "a user-secret system takes the scheme Bearer or Basic");
        }
    }
}
