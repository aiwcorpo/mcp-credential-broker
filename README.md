# mcp-credential-broker

Credential broker platformy MCP (strumień ws-06): jedyne miejsce, w którym leżą poświadczenia użytkowników
do systemów docelowych, per (`sub`, system). Gateway pobiera z niego poświadczenie przy wywołaniu
narzędzia (`resolve`), portal BFF zapisuje je w imieniu zalogowanego użytkownika. Kontrakt: C4 z
`mcp-contracts` 2.0.0 (`openapi/credential-broker.v1.yaml`), audyt C8, zdarzenie C4.3.

Stan: kamień M1 (PAT do Jiry). Co działa, czego jeszcze nie ma i odstępstwa od briefu: [STATUS.md](STATUS.md).

## API w tej wersji

Wszystko po HTTPS z wymaganym certyfikatem klienta z wewnętrznego CA (port 8443 w kontenerze).

| Operacja | CN certyfikatu | Token | Wynik |
| --- | --- | --- | --- |
| `POST /v1/credentials/resolve` | `mcp-gateway` | wewnętrzny JWT C2, wariant użytkownika, `aud=mcp-credential-broker` | `200 {scheme, value, type, expiresAt, cacheTtlSeconds}` z `Cache-Control: no-store`, `409 credential_required` |
| `PUT /v1/connections/{system}/secret` | `mcp-portal-bff` | token użytkownika po token exchange: `aud` zawiera `mcp-credential-broker`, `azp=mcp-portal-bff` | `200 {status, backendUser, expiresAt}`, `422 secret_invalid` / `identity_mismatch` |
| `GET /v1/systems` | `mcp-gateway`, `mcp-portal-bff` | jak wyżej; od gateway'a także wariant serwisowy C2 (CC-030) | lista systemów z konfiguracji |
| `GET /actuator/health` | dowolny z wewnętrznego CA | brak | `UP`/`DOWN` |

Pozostałe operacje C4 (`GET /v1/connections`, `oauth/*`, `DELETE`, `purge`) odpowiadają
`404 not_found_or_denied` do czasu M2-M4, tak samo jak każda nieznana ścieżka i metoda. C4 nie ma 500:
nieoczekiwany błąd i niedostępna zależność (OpenBao, PostgreSQL, Redis, JWKS gateway'a lub IdP) dają
`503 upstream_unavailable`.

Kolejność kontroli w `CallerAuthenticationFilter`: operacja znana (inaczej 404), CN dozwolony dla operacji
zgodnie z `x-allowed-client-cn` (inaczej 403), token pasujący do CN (inaczej 401). `sub` zawsze pochodzi z
tokenu; ścieżka, query i ciało nie mogą go wskazać (nieznane pola w JSON -> 400). Ciało jest ograniczone do
16 KB liczonych przy czytaniu, więc limit działa także dla `Transfer-Encoding: chunked` bez `Content-Length`.

Wewnętrzny JWT C2 sprawdzany jest dokładnie według wektorów `test-vectors/jwt` z 2.0.0 (wszystkie 43
przechodzą, także co do powodu odrzucenia): tylko ES256, `kid` z JWKS gateway'a, podpis, kształt claimów
wariantu, `iss`, `aud` jako napis, `exp` z tolerancją 30 s, `iat` nie z przyszłości, czas życia do 60 s,
`rid == X-Request-Id`, wariant serwisowy tylko dla `GET /v1/systems`, `tool` wymagany przy `resolve` i
zabroniony przy `GET /v1/systems` (CC-038), `vsc` według wzorców identyfikatorów i najwyżej 50 na pole
(CC-056), `jti` jednorazowy (Redis, `SET NX EX` pod `jti:mcp-credential-broker:`). Opublikowane klucze testowe
(`kid` z prefiksem `test-` i, niezależnie od `kid`, klucze o skrócie SPKI z `test-vectors/keys`) są odrzucane
z powodem `test_key_not_allowed`, chyba że `MCP_ALLOW_TEST_KEYS=true` (CC-044).

`PUT secret` woła whoami systemu z nowym sekretem (Jira DC: `GET /rest/api/2/myself`, bez podążania za
przekierowaniami, TLS z zaufaniem do wewnętrznego CA) i porównuje użytkownika z claimem SSO. Odrzucony
sekret albo cudzy PAT nie jest nigdzie zapisywany. Zastąpienie istniejącego połączenia publikuje
`credential.invalidated` (CC-046). `subjectToken` w `resolve` dla systemu, który nie jest `token-exchange`,
daje 400.

Porównanie tożsamości (C4.1), ustawienie `broker.systems.<system>.identity-claim`:

- `preferred_username` (domyślnie): nazwa z whoami musi być równa claimowi; wielkość liter ignorowana tylko
  wtedy, gdy obie nazwy są w ASCII (składanie wielkości liter poza ASCII skleja różne znaki, np. KELVIN SIGN
  z `k`).
- `email`: dodatkowo token musi mieć `email_verified: true`; brak claimu albo `false` daje
  `identity_mismatch`. W części IdP użytkownik sam zmienia e-mail, więc niezweryfikowany adres pozwoliłby
  podpiąć cudze konto.
- Entra ID: `email` bywa zmienny i niezweryfikowany, a Entra domyślnie nie wystawia `email_verified`, więc tryb
  `email` z Entra zawsze da `identity_mismatch`. Zalecenie: oprzeć porównanie na claimie, którego użytkownik
  nie zmienia (`oid` albo UPN z domeny kontrolowanej przez firmę), z mapowaniem na login w Jirze. Takie
  mapowanie to nowy tryb `identity-claim` do dodania razem z konfiguracją produkcyjnego IdP (D4).

## Przechowywanie

- OpenBao (D6): wartość jest szyfrowana Transit (`transit/encrypt/mcp-credential-broker`), a szyfrogram
  zapisywany w KV v2 pod `secret/data/mcp/connections/<sha256(sub)>/<system>/<wersja>`. Każdy `PUT` pisze nową
  wersję obok starej, przełącza na nią wiersz w bazie i dopiero potem usuwa starą ścieżkę razem ze wszystkimi
  wersjami KV, więc błąd w połowie nie niszczy poprzedniego poświadczenia, a stare PAT-y nie zostają w
  historii KV. Odszyfrowany rekord zawiera właściciela (`sub`, `system`) i jest z nim porównywany: szyfrogram
  przeniesiony pod cudzą ścieżkę daje 503, nie cudzy sekret.
- Token OpenBao: logowanie AppRole, potem `auth/token/renew-self` po 75% dzierżawy; przy zbliżaniu się do
  `token_max_ttl` albo nieudanym odnowieniu ponowne logowanie, a gdy i ono się nie uda (np. wygasły
  `secret_id`), broker używa bieżącego tokenu do jego wygaśnięcia i loguje ostrzeżenie.
- PostgreSQL (baza `broker`): tylko metadane (`connection`: typ, stan, `backend_user`, terminy, wersja
  ścieżki), migracje Flyway. `lastUsedAt` zapisywane najwyżej raz na 5 min. Pula połączeń z timeoutem 2 s,
  `statement_timeout` 3 s, timeout gniazda 5 s.
- Redis: `jti` wewnętrznych JWT i publikacja `credential.invalidated`; komendy mieszczą się w ACL użytkownika
  `broker` z `mcp-platform-dev` (`SET`, `PUBLISH`).

Niedostępny OpenBao, PostgreSQL, Redis albo JWKS -> `503 upstream_unavailable` (fail-closed). Klucze
gateway'a pobrane z JWKS są ważne najwyżej 1 h po ostatnim udanym pobraniu; potem, jeśli endpoint nie
odpowiada, `resolve` daje 503 (klucz wycofany przez gateway nie działa w nieskończoność).
Połączenia z OpenBao, JWKS i whoami wymagają `https`, chyba że ustawiono `MCP_ALLOW_PLAIN_HTTP=true`
(tylko lokalny stos). Wartość sekretu jest w pamięci w
`SecretValue`, którego `toString` zwraca maskę; nie trafia do logów, audytu ani komunikatów błędów (sprawdzają to
testy integracyjne na całym wyjściu procesu).

## Audyt (C8)

Jedna linia JSON na zdarzenie na stdout (logger `AUDIT`, osobny appender bez prefiksu), więc działa
`make audit RID=<requestId>` z `mcp-platform-dev`. Zdarzenia: `credential_resolve` (każde `resolve`) i
`connection_change` (każdy `PUT secret`), także odrzucone przed serwisem: zły CN (`forbidden_cn`), za duże
ciało, zły token, błędny JSON (`invalid_request`). Nazwa systemu spoza kontraktu nie trafia do pola `server`.
Logger DEBUG/TRACE warstwy HTTP (Spring MVC, Tomcat, Jackson) jest wyciszany filtrem w
`logback-spring.xml` niezależnie od `logging.level`, bo błąd parsowania JSON cytuje ciało z PAT-em. System docelowy jest w `server`
(`mcp-jira`), `requestId` to `rid` z JWT gateway'a albo `X-Request-Id` od BFF (UUIDv7; brak -> broker
generuje). Znaki spoza ASCII są escapowane, więc wartość z tokenu nie złamie linii.

## Konfiguracja

Zmienne środowiska (nazwy z `mcp-platform-dev`, profil `full`). Pełna lista w
`src/main/resources/application.yml`.

| Zmienna | Znaczenie |
| --- | --- |
| `MCP_BROKER_PORT` | port HTTPS, domyślnie `8443` |
| `MCP_TLS_KEYSTORE`, `MCP_TLS_TRUSTSTORE`, `MCP_TLS_STORE_PASSWORD` | PKCS12 brokera i wewnętrzne CA |
| `MCP_DB_URL`, `MCP_DB_USER`, `MCP_DB_PASSWORD` | PostgreSQL |
| `MCP_REDIS_HOST`, `MCP_REDIS_PORT`, `MCP_REDIS_USER`, `MCP_REDIS_PASSWORD` | Redis (użytkownik ACL) |
| `MCP_BAO_ADDR`, `MCP_BAO_ROLE_ID`, `MCP_BAO_SECRET_ID` | OpenBao i AppRole |
| `MCP_OIDC_ISSUER`, `MCP_OIDC_JWKS_URI`, `MCP_OIDC_AUDIENCE` | tokeny BFF z IdP |
| `MCP_BFF_ALLOWED_AZP` | dozwolone `azp` tokenów BFF, domyślnie `mcp-portal-bff` |
| `MCP_GATEWAY_JWKS_URI` albo `MCP_GATEWAY_JWKS_FILE` | JWKS wewnętrznego JWT (dokładnie jedno z dwóch) |
| `MCP_GATEWAY_TLS_NAME` | nazwa TLS endpointu JWKS (CC-035); host w `MCP_GATEWAY_JWKS_URI` musi być równy |
| `MCP_GATEWAY_ISSUER` | `iss` wewnętrznego JWT, domyślnie `https://mcp-gateway.internal` |
| `MCP_ALLOW_TEST_KEYS` | domyślnie `false`: opublikowane klucze testowe odrzucane; `true` tylko w testach i lokalnie |
| `MCP_JIRA_URL` | adres Jiry (whoami), wymagany |
| `MCP_PORTAL_URL` | baza `connectUrl` w `409 credential_required`, wymagany |
| `MCP_ALLOW_PLAIN_HTTP` | domyślnie `false`; `true` dopuszcza `http` do OpenBao, JWKS i whoami (tylko dev) |

Systemy i typy poświadczeń są w `broker.systems` (YAML). M1 zna tylko `jira` z `user-secret`; konfiguracja
typu, którego ta wersja nie obsługuje, zatrzymuje start.

## Budowanie i testy

Wymaga JDK 25 i Dockera (Testcontainers).

```bash
export JAVA_HOME=/opt/homebrew/Cellar/openjdk@25/25.0.4.1/libexec/openjdk.jdk/Contents/Home
./mvnw -B verify                          # testy jednostkowe, kontraktowe i integracyjne + jar
docker build -t mcp-credential-broker:dev .
```

| Test | Co sprawdza |
| --- | --- |
| `InternalJwtVectorTest` | wszystkie wektory C2 z `mcp-contracts` 2.0.0 (wynik i powód, `allowTestKeys` z wektora), klucz testowy pod produkcyjnym `kid` (SPKI), replay |
| `ReturnPathTest` | walidator `returnPath` (CC-032) na wektorach `return-paths/`, gotowy pod `oauth/start` w M2 |
| `OperationsContractTest` | tabela operacji filtra == metody, ścieżki i `x-allowed-client-cn` z OpenAPI C4 |
| `BrokerIntegrationTest` | mTLS, PostgreSQL, Redis z ACL jak w dev, OpenBao (AppRole, KV v2, Transit), fałszywa Jira; odpowiedzi walidowane schematami OpenAPI, audyt schematem C8, zdarzenie schematem C4.3; brak sekretu w odpowiedziach poza `resolve` i w logach |
| `BrokerIntegrationTest` (awarie) | Redis i PostgreSQL wstrzymane (`docker pause`) -> 503 z audytem; szyfrogram przeniesiony pod cudzą ścieżkę -> 503; ciało chunked 200 KB -> 400 bez whoami; sondy ścieżek -> 404 |
| `OpenBaoClientTest` | `renew-self`, ponowne logowanie przy `token_max_ttl`, praca na ważnym tokenie po nieudanym logowaniu |
| `KeySourceTest` | JWKS gateway'a przeterminowany -> 503, niedostępny JWKS IdP -> 503 zamiast 401 |
| `CredentialServiceTest`, `ConnectionTest`, `AuditLogTest`, `TransportSecurityTest` | fail-closed, wersje sekretów, `email_verified`, porównanie ASCII, `subjectToken`, TTL, `lastUsedAt`, escapowanie audytu, wymóg https |

## Uruchomienie lokalne w `mcp-platform-dev` (ws-01)

### Obraz w compose (profil `full`)

```bash
./mvnw -B package -DskipTests && docker build -t mcp-credential-broker:dev .
cd ../mcp-platform-dev
make up                                   # infrastruktura
./scripts/compose.sh --profile full up -d --no-deps mcp-credential-broker
make pat USER=alice BROKER_URL=https://localhost:18100                  # 200, backendUser alice
make pat USER=alice SECRET=bob-pat BROKER_URL=https://localhost:18100   # 422 identity_mismatch
./scripts/compose.sh --profile full rm -sf mcp-credential-broker
```

`make up-full` uruchamia też gateway i `mcp-jira`; bez ich obrazów (`mcp-gateway:dev`,
`mcp-server-jira:dev`) się nie powiedzie, stąd start samego brokera. W compose broker czyta JWKS gateway'a z
`https://mcp-gateway.internal:8443/.well-known/jwks.json` dopiero przy pierwszym `resolve`, więc startuje
bez gateway'a. Póki działa obok stuba C4, oba mają alias `mcp-credential-broker.internal`; po teście
kontener trzeba usunąć (ostatnia komenda).

### Na hoście

```bash
./mvnw -B package -DskipTests
JAVA_HOME=... scripts/run-dev-host.sh     # https://localhost:18100, sekrety z ../mcp-platform-dev/.secrets/dev.env
```

Skrypt bierze sekrety i certyfikaty z `mcp-platform-dev` przy starcie (nic nie kopiuje do tego repo). Bez
`MCP_GATEWAY_JWKS_URI` używa testowego JWKS z `../mcp-contracts/test-vectors/keys/test-gateway-jwks.json` i
ustawia `MCP_ALLOW_TEST_KEYS=true`, żeby `resolve` dało się wywołać tokenem podpisanym kluczem testowym A
(`test-gateway-jwt-a`). To tylko do pracy lokalnej.

## Struktura

```
pl.aiwcorpo.mcp.broker
├── auth/        mTLS CN, weryfikacja C2 i tokenu BFF, tabela operacji, jti w Redis
├── api/         kontrolery C4, DTO, mapowanie błędów
├── credential/  CredentialService (resolve, PUT secret), metadane połączeń (JDBC)
├── secret/      SecretStore + OpenBao (AppRole, KV v2, Transit), SecretValue
├── system/      SystemRegistry, SystemAdapter (whoami), AtlassianDcAdapter
├── audit/       zdarzenia C8
└── event/       credential.invalidated (Redis pub/sub)
```

Rozszerzenia M2-M4 wchodzą w istniejące miejsca: nowe typy poświadczeń w `CredentialType` i
`SystemRegistry`, OAuth i revoke w `SystemAdapter`, refresh token w `StoredCredential`, nowe operacje w
`Operation` (test kontraktowy pilnuje zgodności z OpenAPI).
