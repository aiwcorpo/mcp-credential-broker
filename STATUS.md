# Status ws-06 (mcp-credential-broker)

Kamień: **M1** (`PUT secret` + `resolve` dla `user-secret` Jira, OpenBao KV v2 + Transit, audyt C8, mTLS + JWT
z `x-allowed-client-cn`). Kontrakty: `mcp-contracts` `v2.1.1` (od 2026-10-27, wcześniej 2.0.0 i 1.1.0). M2-M4 nie są
zaczęte.

## M1: zrobione

| Element | Stan |
| --- | --- |
| `POST /v1/credentials/resolve` | tylko CN `mcp-gateway` + wewnętrzny JWT C2 (wariant użytkownika); `200` z `Cache-Control: no-store` i `Pragma: no-cache`, `cacheTtlSeconds` <= 60 i nie dłużej niż do `expiresAt`; `409 credential_required` z `connectUrl`; `503` przy niedostępnym OpenBao/Redis |
| `PUT /v1/connections/{system}/secret` | tylko CN `mcp-portal-bff` + token z IdP (`aud` brokera, `azp=mcp-portal-bff`); whoami Jiry, porównanie z `preferred_username`; `422 secret_invalid` / `identity_mismatch` bez zapisu |
| `GET /v1/systems` | gateway (także wariant serwisowy, CC-030) i BFF; potrzebne gateway'owi przy starcie |
| `GET /v1/connections` | przeniesione do M1 (decyzja człowieka 2026-10-27): tylko CN `mcp-portal-bff`, połączenia `sub` z tokenu, statusy C4 (`connected`, `expiring`, `expired`, `revoked`, `error`), bez wartości sekretu |
| `DELETE /v1/connections/{system}` | przeniesione do M1: usuwa sekret z OpenBao (wszystkie wersje KV), potem metadane, publikuje `credential.invalidated`, audyt `connection_change`; idempotentne (204 także gdy nic nie było, wtedy bez zdarzenia); nieznany system -> 400; odwołanie u dostawcy dotyczy tylko `user-oauth` (M2) |
| Weryfikacja C2 | wszystkie 51 wektorów `test-vectors/jwt` 2.1.1 zgodne co do wyniku i powodu; klucze testowe odrzucane po `kid` i po SPKI |
| `SecretStore` na OpenBao | AppRole, Transit encrypt/decrypt, KV v2, powiązanie szyfrogramu z (`sub`, system) |
| Metadane | PostgreSQL `connection` (Flyway), bez wartości sekretów |
| Audyt C8 | `credential_resolve`, `connection_change` (także odrzucenia na etapie tokenu), walidowane schematem w testach |
| `credential.invalidated` | publikowane przy zastąpieniu istniejącego połączenia (DELETE i purge to M2/M4) |
| Obraz | `mcp-credential-broker:dev` (`eclipse-temurin:25-jre-alpine` przypięty digestem, użytkownik bez roota) |

### Dowody

```
./mvnw -B verify
Tests run: 109, Failures: 0, Errors: 0, Skipped: 0   (BUILD SUCCESS, mcp-contracts 2.1.1)
  InternalJwtVectorTest 55, BrokerIntegrationTest 28, CredentialServiceTest 10, OperationsContractTest 3,
  OpenBaoClientTest 3, KeySourceTest 3, ConnectionTest 2, AuditLogTest 2, ReturnPathTest 2,
  TransportSecurityTest 1
```

Test akceptacyjny w `mcp-platform-dev` @ `4731dd5` (obraz `mcp-credential-broker:dev` na kontraktach 2.0.0,
`./scripts/compose.sh --profile full up -d --no-deps mcp-credential-broker`, prawdziwy Keycloak, OpenBao,
PostgreSQL, Redis z ACL, mock Jiry; bez resetu środowiska, kontener usunięty po teście; wcześniejsze przebiegi
po M1 i po przeglądzie dały ten sam wynik, migracja V2 przeszła na danych z M1):

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

## Przeniesione do M1: `GET /v1/connections` i `DELETE /v1/connections/{system}` (2026-10-27)

Decyzja człowieka: test integracyjny portalu (przeglądarka -> BFF -> prawdziwy broker) potrzebował listy
połączeń. OAuth, refresh, purge i reszta M2-M4 nadal poza zakresem.

| Test | Co sprawdza |
| --- | --- |
| `listsAndDeletesOnlyTheCallersConnections` | lista walidowana schematem `Connection` z OpenAPI 2.0.0, bez wartości sekretu; `?sub=` w liście i `DELETE`, `sub` w ciele `DELETE` i `sub` w miejscu systemu (400) nie dotykają cudzego połączenia; po `DELETE`: 204, `credential.invalidated` (schemat), audyt `disconnected`, brak wiersza i wpisu w OpenBao, `resolve` -> 409; drugi `DELETE` 204 bez zdarzenia |
| `listedStatusFollowsStoredStateAndExpiry` | `expired`, `revoked`, `error` na liście; `resolve` dla nich -> 409 |
| `OperationsContractTest` | tabela operacji obejmuje `listConnections` i `deleteConnection`; niezrobione zostają `startOAuth`, `completeOAuth`, `purgeUser` |

`400` dla nieznanego systemu w `DELETE` nie jest wymienione w odpowiedziach tej operacji w C4 (C12 ma je od
CC-054); ciało ma kształt `Error`.

## Przejście na `mcp-contracts` 2.0.0 (2026-10-27)

| Wymaganie 2.0.0 | Stan |
| --- | --- |
| `tool` per metoda (CC-038) | wymagany przy `resolve` (`tool_missing`), zabroniony przy `GET /v1/systems` (`tool_not_allowed`); reguła w tabeli `Operation` |
| klucze testowe (CC-044) | powód `test_key_not_allowed`; odrzucenie po `kid` `test-*` i po skrócie SPKI opublikowanych kluczy; ustawienie `MCP_ALLOW_TEST_KEYS` (zamiast `MCP_REJECT_TEST_KIDS`) |
| harness wektorów | czyta `verifier.allowTestKeys`, reguły metod z serwera i z `Operation`; 43/43 wektorów, wynik i powód |
| `vsc` (CC-056) | wzorce identyfikatorów per pole, 1..50 elementów, unikalne |
| `X-Request-Id` (CC-047) | przyjmowany od BFF, w każdej odpowiedzi (test na wszystkich odpowiedziach klasy integracyjnej) |
| `credential.invalidated` po zastąpieniu (CC-046) | było |
| pojedynczy token w `PUT secret` (CC-049) | sekret musi być jednym tokenem bez spacji i znaków sterujących, inaczej `422 secret_invalid` bez wywołania whoami |
| 503 we wszystkich operacjach (CC-064) | było; ciała błędów walidowane schematem `Error` |
| audyt 2.0.0 (CC-031) | testy walidują schematem 2.0.0; broker nie emituje `resource` |
| `returnPath` (CC-032) | walidator `ReturnPath` z testem na wektorach; użyty w M2 (`oauth/start`) |

## Przejście na `mcp-contracts` 2.1.1 (2026-10-27)

Schemat Cedar bajtowo jak w 2.0.x; zmieniła się wersja zależności w `pom.xml` (artefakty z `~/.m2`).

| Pozycja | Stan |
| --- | --- |
| CC-073: whoami Confluence DC | `AtlassianDcAdapter.Product`: Jira `GET /rest/api/2/myself` (login w `name`), Confluence `GET /rest/api/user/current` (login w `username`); produkt wybiera `SystemRegistry` po id systemu (adapter `atlassian-dc` obsługuje tylko `jira` i `confluence`). Testy: `confluenceIdentityIsTakenFromUsernameOfUserCurrent` (connected, `backendUser` = username, bez wywołania whoami Jiry), `anotherPersonsConfluencePatIsRejectedAndNothingIsStored` (`identity_mismatch`, brak wiersza, `resolve` -> 409), `confluencePatTheSystemRejectsIsNotStored` (401 -> `secret_invalid`); Jira bez regresji (dotychczasowe testy) |
| Konfiguracja Confluence | system `confluence` nie jest w `application.yml` (wymagany adres zepsułby start tam, gdzie go nie ma); włącza się zmiennymi `BROKER_SYSTEMS_CONFLUENCE_*` (README). Dodanie `MCP_CONFLUENCE_URL` do `mcp-platform-dev` i mocka `/rest/api/user/current` to prace ws-01 |
| CC-069/070: wektory JWT (9 nowych, razem 51) | wszystkie zgodne; w harnessie testowym `server/discover` dopisane do metod dozwolonych dla wariantu serwisowego (broker nie obsługuje JSON-RPC, więc kod produkcyjny bez zmian: wariant serwisowy nadal tylko `GET /v1/systems`) |
| CC-071 (audyt `authentication`), CC-072, CC-074, CC-075, CC-076, CC-077 | nie dotyczą M1 brokera (broker nie emituje `authentication`, nie zwraca treści z systemów, nie obsługuje potwierdzeń); nic do zrobienia |
| 2.1.1: `no-store` na potwierdzeniach, zamknięta lista pól `authentication` | dotyczy gateway'a, BFF i startera, nie brokera (broker ma `no-store` na `resolve` od M1) |

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
- `MCP_ALLOW_PLAIN_HTTP` i `MCP_PORTAL_URL` są w `docker-compose.yml` od `mcp-platform-dev` `4731dd5`.

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
- **Lista kluczy testowych po SPKI** jest w kodzie (`InternalJwtVerifier.TEST_KEY_SPKI_SHA256`, cztery klucze EC
  z `test-vectors/keys`); test pilnuje zgodności z jarem `test-vectors`. Nowy klucz testowy w kontraktach
  wymaga dopisania skrótu.

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
