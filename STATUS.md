# Status ws-06 (mcp-credential-broker)

Kamień: **M1** (`PUT secret` + `resolve` dla `user-secret` Jira, OpenBao KV v2 + Transit, audyt C8, mTLS + JWT
z `x-allowed-client-cn`). Kontrakty: `mcp-contracts` `v1.1.0`. M2-M4 nie są zaczęte.

## M1: zrobione

| Element | Stan |
| --- | --- |
| `POST /v1/credentials/resolve` | tylko CN `mcp-gateway` + wewnętrzny JWT C2 (wariant użytkownika); `200` z `Cache-Control: no-store` i `Pragma: no-cache`, `cacheTtlSeconds` <= 60 i nie dłużej niż do `expiresAt`; `409 credential_required` z `connectUrl`; `503` przy niedostępnym OpenBao/Redis |
| `PUT /v1/connections/{system}/secret` | tylko CN `mcp-portal-bff` + token z IdP (`aud` brokera, `azp=mcp-portal-bff`); whoami Jiry, porównanie z `preferred_username`; `422 secret_invalid` / `identity_mismatch` bez zapisu |
| `GET /v1/systems` | gateway (także wariant serwisowy, CC-030) i BFF; potrzebne gateway'owi przy starcie |
| Weryfikacja C2 | wszystkie 38 wektorów `test-vectors/jwt` zgodne co do wyniku i powodu; `kid` `test-` odrzucany domyślnie |
| `SecretStore` na OpenBao | AppRole, Transit encrypt/decrypt, KV v2, powiązanie szyfrogramu z (`sub`, system) |
| Metadane | PostgreSQL `connection` (Flyway), bez wartości sekretów |
| Audyt C8 | `credential_resolve`, `connection_change` (także odrzucenia na etapie tokenu), walidowane schematem w testach |
| `credential.invalidated` | publikowane przy zastąpieniu istniejącego połączenia (DELETE i purge to M2/M4) |
| Obraz | `mcp-credential-broker:dev` (`eclipse-temurin:25-jre-alpine` przypięty digestem, użytkownik bez roota) |

### Dowody

```
./mvnw -B verify
Tests run: 69, Failures: 0, Errors: 0, Skipped: 0   (BUILD SUCCESS)
  InternalJwtVectorTest 41, BrokerIntegrationTest 15, CredentialServiceTest 6,
  OperationsContractTest 3, ConnectionTest 2, AuditLogTest 2
```

Test akceptacyjny w `mcp-platform-dev` (obraz `mcp-credential-broker:dev`, usługa z profilu `full`
uruchomiona z `--no-deps`, prawdziwy Keycloak, OpenBao, PostgreSQL, Redis z ACL, mock Jiry):

```
$ make pat USER=alice BROKER_URL=https://localhost:18100
{"httpStatus": 200, "status": "connected", "backendUser": "alice", "expiresAt": null}
$ make pat USER=alice SECRET=bob-pat BROKER_URL=https://localhost:18100
{"httpStatus": 422, "error": "identity_mismatch"}
```

Dodatkowo (broker na hoście, `scripts/run-dev-host.sh`, JWKS testowy): `resolve` z tokenem C2 podpisanym
kluczem testowym A dla `sub` alice z Keycloaka -> `200`, `value` == `alice-pat`, `Cache-Control: no-store`;
ten sam token drugi raz -> `401` (`replayed_jti` przez Redis z ACL `broker`); w logach brokera i OpenBao
0 wystąpień `alice-pat`/`bob-pat`. Audyt `connection_change` i `credential_resolve` z `requestId` w stdout.
Bez certyfikatu i z certyfikatem obcego CA: zerwany handshake.

### Definition of Done (punkty M1)

| Punkt | Test |
| --- | --- |
| żaden endpoint poza `resolve` nie zwraca wartości sekretu | `BrokerIntegrationTest.noResponseOtherThanResolveCarriesASecret` (wszystkie odpowiedzi klasy, ciała i nagłówki) + logi procesu w kilku testach |
| BFF nie zmieni połączenia innego użytkownika (podmieniony `sub` w ciele/ścieżce) | `portalCannotNameAnotherUser`: `sub` w ciele -> 400, `?sub=` ignorowane, `sub` w ścieżce -> 404; u ofiary nic |
| PAT innej osoby -> `identity_mismatch`, nic nie zapisane | `anotherPersonsPatIsRejectedAndNothingIsStored`: brak wiersza, brak wpisu w OpenBao, istniejące połączenie bez zmian; potwierdzone `make pat` |
| `resolve` zwraca `cacheTtlSeconds` <= 60 | testy integracyjne i `CredentialServiceTest.cacheTtlNeverOutlivesTheCredential` |

Punkty DoD o OAuth, `DELETE`/`purge`, revoke i odświeżaniu należą do M2-M4.

## Odstępstwa od briefu

- **Ścieżka w KV:** `secret/data/mcp/connections/<sha256(sub)>/<system>` zamiast `mcp/<system>/<sub-hash>`
  z briefu, bo polityka AppRole w `mcp-platform-dev` (`openbao/init.sh`) daje dostęp tylko do
  `secret/data/mcp/connections/*`. Kolejność `<sub-hash>/<system>` pozwala w M4 wylistować wszystkie
  sekrety użytkownika przy `purge` (polityka ma `list` na metadanych).
- **"Envelope" przez Transit:** wartość jest szyfrowana bezpośrednio `transit/encrypt` (klucz nie opuszcza
  OpenBao), bez lokalnych kluczy danych z `transit/datakey`; polityka dev nie daje `datakey`, a dla
  sekretów do 4 KB osobny klucz danych nic nie wnosi.
- **Brak Spring Security filter chain:** uwierzytelnienie to para (CN, token) zależna od operacji, więc jest
  jednym filtrem (`CallerAuthenticationFilter`) z tabelą operacji sprawdzaną testem względem OpenAPI. Z
  Spring Security używany jest tylko `NimbusJwtDecoder` dla tokenów BFF.
- **`credential.invalidated` po zastąpieniu sekretu** i **`X-Request-Id` od BFF**: zrobione, zgłoszone jako
  propozycje CC (niżej).
- **Profil `full`:** `make up-full` nie przejdzie, dopóki nie ma obrazów `mcp-gateway:dev` i
  `mcp-server-jira:dev` (`pull_policy: never`). Test akceptacyjny uruchomiony na usłudze brokera z profilu
  `full` przez `./scripts/compose.sh --profile full up -d --no-deps mcp-credential-broker`, po teście
  kontener usunięty (ten sam alias DNS co stub C4). Nic w `mcp-platform-dev` nie było edytowane.

## Propozycje zmian kontraktów (dopisane do `mcp-contracts/CONTRACT_CHANGES.md`, status `open`)

1. `CC-??? | C4 | credential.invalidated także po zastąpieniu sekretu` (patch).
2. `CC-??? | C4/C8 | X-Request-Id w wywołaniach BFF -> broker` (minor: opcjonalny nagłówek).

## Otwarte pytania

- **Kod błędu dla systemu bez `user-secret`** (np. `PUT .../gitlab/secret` w M1, `opensearch` docelowo):
  teraz `400 invalid_request`. Kontrakt nie ma osobnego kodu; jeśli portal ma to pokazywać inaczej, potrzebny
  wpis CC.
- **`resolve` dla systemu nieskonfigurowanego w brokerze:** `400 invalid_request` (nie `409`, bo połączenie i
  tak nie byłoby możliwe). Do potwierdzenia z ws-05.
- **Porównanie tożsamości:** bez rozróżniania wielkości liter (`Locale.ROOT`), domyślnie
  `preferred_username` == `name` z whoami. Prod (Entra/Okta + Jira DC) może wymagać e-maila: ustawienie
  `identity-claim: email` per system.
- **`expiresAt` w przeszłości przy `PUT secret`:** `400 invalid_request`.
- **Prefiksy Redis:** używane `jti:mcp-credential-broker:*` (SET NX EX) i kanał `credential.invalidated`
  (PUBLISH); `broker:*` jeszcze nieużywany. Lista komend ACL z `redis/start.sh` wystarcza; health indicator
  Redis wyłączony (wymaga `INFO`).
- **1.2.0:** w kopii roboczej `mcp-contracts` są wektory `broker-resolve-without-tool` (CC-038) i
  `test-kid-rejected-by-default` (CC-044, pole `allowTestKeys` w `verifier`). Weryfikator już wymaga `tool`
  w wariancie użytkownika i domyślnie odrzuca `test-` kid; przy przejściu na 1.2.0 test wektorów musi
  czytać `allowTestKeys`, a powody odrzucenia (`tool_missing`, `test_key_not_allowed`) trzeba uzgodnić z
  nazwami w kodzie.

## Czego potrzebuje gateway (ws-05)

- mTLS do `https://mcp-credential-broker.internal:8443` (z hosta `https://localhost:18100`) z certyfikatem
  CN `mcp-gateway`; weryfikacja nazwy `MCP_BROKER_TLS_NAME` (CC-035).
- Nowy JWT C2 na każde żądanie: `aud=mcp-credential-broker`, wariant użytkownika z `tool`, `rid` ==
  nagłówek `X-Request-Id`, `exp - iat` <= 60, nowy `jti`; wariant serwisowy tylko na `GET /v1/systems`.
- JWKS pod `https://mcp-gateway.internal:8443/.well-known/jwks.json` (broker pobiera przy pierwszym
  użyciu, odświeża co 5 min i przy nieznanym `kid`, nie częściej niż co 10 s); certyfikat z SAN
  `mcp-gateway.internal`, zaufany przez wewnętrzne CA. Produkcyjne `kid` nie mogą zaczynać się od `test-`.
- Cache wartości najwyżej `cacheTtlSeconds`, subskrypcja `credential.invalidated` (dziś wysyłane przy
  zastąpieniu PAT).
- `409 credential_required` -> C10 `credential_required` z `connectUrl`; `503` -> `upstream_unavailable`;
  `401`/`403` -> błąd konfiguracji gateway'a (nie dotyczy użytkownika).
- Do testów bez brokera w compose: `scripts/run-dev-host.sh` (testowy JWKS z `mcp-contracts`).
