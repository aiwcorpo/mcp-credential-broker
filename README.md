# mcp-credential-broker

Credential broker platformy MCP (strumień ws-06): jedyne miejsce, w którym leżą poświadczenia użytkowników
do systemów docelowych, per (`sub`, system). Gateway pobiera z niego poświadczenie przy wywołaniu
narzędzia (`resolve`), portal BFF zapisuje je w imieniu zalogowanego użytkownika. Kontrakt: C4 z
`mcp-contracts` 1.1.0 (`openapi/credential-broker.v1.yaml`), audyt C8, zdarzenie C4.3.

Stan: kamień M1 (PAT do Jiry). Co działa, czego jeszcze nie ma i odstępstwa od briefu: [STATUS.md](STATUS.md).

## API w tej wersji

Wszystko po HTTPS z wymaganym certyfikatem klienta z wewnętrznego CA (port 8443 w kontenerze).

| Operacja | CN certyfikatu | Token | Wynik |
| --- | --- | --- | --- |
| `POST /v1/credentials/resolve` | `mcp-gateway` | wewnętrzny JWT C2, wariant użytkownika, `aud=mcp-credential-broker` | `200 {scheme, value, type, expiresAt, cacheTtlSeconds}` z `Cache-Control: no-store`, `409 credential_required` |
| `PUT /v1/connections/{system}/secret` | `mcp-portal-bff` | token użytkownika po token exchange: `aud` zawiera `mcp-credential-broker`, `azp=mcp-portal-bff` | `200 {status, backendUser, expiresAt}`, `422 secret_invalid` / `identity_mismatch` |
| `GET /v1/systems` | `mcp-gateway`, `mcp-portal-bff` | jak wyżej; od gateway'a także wariant serwisowy C2 (CC-030) | lista systemów z konfiguracji |
| `GET /actuator/health` | dowolny z wewnętrznego CA | brak | `UP`/`DOWN` |

Pozostałe operacje C4 (`GET /v1/connections`, `oauth/*`, `DELETE`, `purge`) odpowiadają `404` do czasu M2-M4.

Kolejność kontroli w `CallerAuthenticationFilter`: operacja znana (inaczej 404), CN dozwolony dla operacji
zgodnie z `x-allowed-client-cn` (inaczej 403), token pasujący do CN (inaczej 401). `sub` zawsze pochodzi z
tokenu; ścieżka, query i ciało nie mogą go wskazać (nieznane pola w JSON -> 400).

Wewnętrzny JWT C2 sprawdzany jest dokładnie według wektorów `test-vectors/jwt` (wszystkie 38 przechodzą,
także co do powodu odrzucenia): tylko ES256, `kid` z JWKS gateway'a (w produkcji bez prefiksu `test-`),
podpis, kształt claimów wariantu, `iss`, `aud` jako napis, `exp` z tolerancją 30 s, `iat` nie z przyszłości,
czas życia do 60 s, `rid == X-Request-Id`, wariant serwisowy tylko dla `GET /v1/systems`, `jti` jednorazowy
(Redis, `SET NX EX` pod `jti:mcp-credential-broker:`).

`PUT secret` woła whoami systemu z nowym sekretem (Jira DC: `GET /rest/api/2/myself`, bez podążania za
przekierowaniami) i porównuje użytkownika z claimem SSO (`preferred_username`, bez rozróżniania wielkości
liter; konfigurowalne na `email`). Odrzucony sekret albo cudzy PAT nie jest nigdzie zapisywany. Zastąpienie
istniejącego połączenia publikuje `credential.invalidated` (propozycja CC w `mcp-contracts`).

## Przechowywanie

- OpenBao (D6): wartość jest szyfrowana Transit (`transit/encrypt/mcp-credential-broker`), a szyfrogram
  zapisywany w KV v2 pod `secret/data/mcp/connections/<sha256(sub)>/<system>`. Odszyfrowany rekord zawiera
  właściciela (`sub`, `system`) i jest z nim porównywany, więc szyfrogram przeniesiony pod cudzą ścieżkę
  nie da się użyć. Logowanie AppRole, token odnawiany po 75% czasu dzierżawy.
- PostgreSQL (baza `broker`): tylko metadane (`connection`: typ, stan, `backend_user`, terminy), migracje
  Flyway.
- Redis: `jti` wewnętrznych JWT i publikacja `credential.invalidated`; komendy mieszczą się w ACL użytkownika
  `broker` z `mcp-platform-dev` (`SET`, `PUBLISH`).

Niedostępny OpenBao albo Redis -> `503 upstream_unavailable` (fail-closed). Wartość sekretu jest w pamięci w
`SecretValue`, którego `toString` zwraca maskę; nie trafia do logów, audytu ani komunikatów błędów (sprawdzają to
testy integracyjne na całym wyjściu procesu).

## Audyt (C8)

Jedna linia JSON na zdarzenie na stdout (logger `AUDIT`, osobny appender bez prefiksu), więc działa
`make audit RID=<requestId>` z `mcp-platform-dev`. Zdarzenia: `credential_resolve` (każde `resolve`, także
odrzucone na etapie tokenu) i `connection_change` (każdy `PUT secret`). System docelowy jest w `server`
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
| `MCP_REJECT_TEST_KIDS` | domyślnie `true`: `kid` z prefiksem `test-` odrzucany; `false` tylko w testach |
| `MCP_JIRA_URL` | adres Jiry (whoami) |
| `MCP_PORTAL_URL` | baza `connectUrl` w `409 credential_required`, domyślnie `http://localhost:18090` |

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
| `InternalJwtVectorTest` | wszystkie wektory C2 z `mcp-contracts` 1.1.0 (wynik i powód), odrzucenie `test-` kid, replay |
| `OperationsContractTest` | tabela operacji filtra == metody, ścieżki i `x-allowed-client-cn` z OpenAPI C4 |
| `BrokerIntegrationTest` | mTLS, PostgreSQL, Redis z ACL jak w dev, OpenBao (AppRole, KV v2, Transit), fałszywa Jira; odpowiedzi walidowane schematami OpenAPI, audyt schematem C8, zdarzenie schematem C4.3; brak sekretu w odpowiedziach poza `resolve` i w logach |
| `CredentialServiceTest`, `ConnectionTest`, `AuditLogTest` | fail-closed przy awarii OpenBao, sprzątanie po błędzie bazy, TTL, statusy, escapowanie audytu |

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
dopuszcza `kid` z prefiksem `test-`, żeby `resolve` dało się wywołać tokenem podpisanym kluczem testowym A
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
