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
Tests run: 87, Failures: 0, Errors: 0, Skipped: 0   (BUILD SUCCESS)
  InternalJwtVectorTest 41, BrokerIntegrationTest 22, CredentialServiceTest 10, OperationsContractTest 3,
  OpenBaoClientTest 3, KeySourceTest 3, ConnectionTest 2, AuditLogTest 2, TransportSecurityTest 1
```

Test akceptacyjny w `mcp-platform-dev` @ `8d459c1` (obraz `mcp-credential-broker:dev`, usługa z profilu
`full` przez `compose run --no-deps -e MCP_ALLOW_PLAIN_HTTP=true -e MCP_PORTAL_URL=...`, prawdziwy Keycloak,
OpenBao, PostgreSQL, Redis z ACL, mock Jiry; powtórzony po poprawkach z przeglądu, bez resetu środowiska:
migracja V2 przeszła na istniejących danych, a PAT alice zapisany w M1 bez wersji ścieżki został zastąpiony
wersjonowanym):

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

## Przegląd M1 (2026-10-27): znaleziska i poprawki

| # | Znalezisko | Co zrobione |
| --- | --- | --- |
| M1 | `identity-claim=email` bez `email_verified` | tryb `email` wymaga `email_verified: true` (brak/`false` -> `identity_mismatch`); domyślnie `preferred_username`; zalecenie dla Entra w README; test `emailIdentityNeedsAVerifiedEmail` |
| M2 | nie każde `resolve`/`PUT` w audycie | audyt także dla 403 (`forbidden_cn`), za dużego ciała, złego JSON i walidacji (`invalid_request`), z `sub` gdy token był poprawny; walidacja systemu, `scopes` i `subjectToken` przeniesiona do serwisu; test `rejectionsBeforeTheServiceAreAudited` |
| M3 | HTTP do OpenBao/whoami, whoami bez CA | `https` wymagane dla OpenBao, JWKS gateway'a i IdP oraz whoami, chyba że `MCP_ALLOW_PLAIN_HTTP=true`; jeden klient wewnętrzny z zaufaniem do CA z SSL bundle, bez certyfikatu klienta i przekierowań; `TransportSecurityTest` |
| M4 | brak odnawiania tokenu OpenBao | `auth/token/renew-self` po 75% dzierżawy, logowanie AppRole przy `token_max_ttl` lub błędzie odnowienia, przy nieudanym logowaniu praca na ważnym tokenie do jego wygaśnięcia; `OpenBaoClientTest` |
| M5 | brak testów zabezpieczeń | testy: szyfrogram pod cudzą ścieżką -> 503, Redis i PostgreSQL wstrzymane -> 503 z audytem, JWKS gateway'a przeterminowany i JWKS IdP niedostępny -> 503, sondy ścieżek -> 404 |
| M6 | baza niedostępna -> 500, Hikari 30 s | wyjątki dostępu do danych (zasób, transient, recoverable) -> 503 i audyt `database_unavailable`; `connection-timeout` 2 s, `socketTimeout` 5 s, `statement_timeout` 3 s |
| L7 | `toLowerCase` łączy znaki spoza ASCII | równość dokładna albo bez wielkości liter tylko dla ASCII |
| L8 | JWKS niedostępny -> 401, klucze bez limitu, monitor przy pobieraniu | niedostępny JWKS IdP/gateway'a -> 503; klucze gateway'a ważne 1 h od ostatniego pobrania (`jwks-max-stale`); pobranie w tle pod `tryLock`, blokuje tylko pierwsze |
| L9 | stare wersje w KV, `deleteQuietly` usuwał poprzednie | ścieżka z wersją (`.../<system>/<wersja>`, kolumna `secret_version`, migracja V2): nowa wartość obok starej, przełączenie wiersza, potem usunięcie starej ścieżki ze wszystkimi wersjami; przy błędzie usuwana tylko nowa |
| L10 | DEBUG warstwy HTTP cytuje PAT | `HttpLayerDebugGuard` (turbo filter w `logback-spring.xml`) odrzuca DEBUG/TRACE z `org.springframework.web`, `org.springframework.http`, Tomcat, Jackson; test w kontekście |
| L11 | limit tylko po `Content-Length` (także przegląd automatyczny) | `LimitedBodyRequest` liczy bajty faktycznie czytane i przerywa po 16 KB; test `chunkedBodyOverTheLimitIsNotRead` (200 KB chunked -> 400, bez whoami, bez zapisu) |
| L12 | adresy dev jako domyślne | `MCP_PORTAL_URL` i `MCP_JIRA_URL` wymagane |
| L13 | `not_found`, 500 spoza OpenAPI | 404 `not_found_or_denied` (CC-012); każdy nieoczekiwany błąd -> 503 `upstream_unavailable` |
| L14 | martwy kod | usunięte `ConfiguredSystem.serverId()`, `SecretValue.equals/hashCode`, gałąź `ReplayGuardUnavailableException` w handlerze, `Caller.Offboarding` (wróci z `purge` w M4) |
| L15 | `CC-???` w STATUS | CC-046, CC-047 |
| L16 | zapis `lastUsedAt` przy każdym `resolve` | najwyżej raz na 5 min |
| L17 | `subjectToken` przyjmowany i ignorowany | 400 `invalid_request` dla systemów innych niż `token-exchange` |
| L18, L19 | tożsamość = sam CN; `subHash` bez klucza | informacyjnie, bez zmian (wynika z C4; `sub` jest i tak w bazie) |

## Odstępstwa od briefu

- **Ścieżka w KV:** `secret/data/mcp/connections/<sha256(sub)>/<system>/<wersja>` zamiast
  `mcp/<system>/<sub-hash>` z briefu, bo polityka AppRole w `mcp-platform-dev` (`openbao/init.sh`) daje
  dostęp tylko do `secret/data/mcp/connections/*`. Kolejność `<sub-hash>/<system>` pozwala w M4 wylistować
  wszystkie sekrety użytkownika przy `purge` (polityka ma `list` na metadanych). Wpisy z M1 bez wersji są
  czytane pod starą ścieżką i znikają przy następnym `PUT`.
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
  `full` przez `compose run --no-deps`, po teście kontener usunięty (ten sam alias DNS co stub C4). Nic w
  `mcp-platform-dev` nie było edytowane.
- **Prośba do ws-01 (`docker-compose.yml`, usługa `mcp-credential-broker`):** dopisać
  `MCP_ALLOW_PLAIN_HTTP: "true"` (OpenBao, Keycloak i mock Jiry w dev są po HTTP) i
  `MCP_PORTAL_URL: http://localhost:${PORTAL_PORT}`. Bez nich obraz nie wstaje w compose (sprawdzone: odmowa
  startu z komunikatem `must use https`); do tego czasu `-e` przy `compose run`.

## Propozycje zmian kontraktów (dopisane do `mcp-contracts/CONTRACT_CHANGES.md`, status `open`)

1. CC-046 `credential.invalidated` także po zastąpieniu sekretu (patch).
2. CC-047 `X-Request-Id` w wywołaniach BFF -> broker (minor: opcjonalny nagłówek).

## Otwarte pytania

- **Kod błędu dla systemu bez `user-secret`** (np. `PUT .../gitlab/secret` w M1, `opensearch` docelowo):
  teraz `400 invalid_request`. Kontrakt nie ma osobnego kodu; jeśli portal ma to pokazywać inaczej, potrzebny
  wpis CC.
- **`resolve` dla systemu nieskonfigurowanego w brokerze:** `400 invalid_request` (nie `409`, bo połączenie i
  tak nie byłoby możliwe). Do potwierdzenia z ws-05.
- **Porównanie tożsamości w prod:** domyślnie `preferred_username` == `name` z whoami (wielkość liter tylko
  w ASCII); tryb `email` wymaga `email_verified`. Dla Entra potrzebny będzie tryb na niezmiennym claimie
  (`oid` lub UPN) z mapowaniem na login w Jirze; do decyzji przy D4.
- **503 w `PUT secret` i `GET /v1/systems`:** OpenAPI C4 opisuje 503 tylko dla `resolve`, a broker zwraca
  `503 upstream_unavailable` także przy niedostępnej Jirze/OpenBao/bazie w `PUT secret` (kształt `Error` z
  CC-012). Jeśli ma to być w kontrakcie, potrzebny wpis CC (dopisanie odpowiedzi 503, minor).
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
  Gdy JWKS nie odpowiada dłużej niż 1 h, `resolve` daje 503.
- Cache wartości najwyżej `cacheTtlSeconds`, subskrypcja `credential.invalidated` (dziś wysyłane przy
  zastąpieniu PAT).
- `409 credential_required` -> C10 `credential_required` z `connectUrl`; `503` -> `upstream_unavailable`;
  `400` (np. `subjectToken` dla systemu `user-secret`), `401`, `403` -> błąd gateway'a, nie użytkownika.
- Do testów bez brokera w compose: `scripts/run-dev-host.sh` (testowy JWKS z `mcp-contracts`).
