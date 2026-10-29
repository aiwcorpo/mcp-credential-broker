# Status ws-06 (mcp-credential-broker)

Kamień: **M4** (strona brokera: CHANGELOG 4.0.0 kontraktów, CC-133 ... CC-162 dotyczące brokera). Kontrakty: `mcp-contracts` **4.0.0**
(tag v4.0.0, w `~/.m2`). Poniżej sekcja M4, dalej M3, M2 i M1 bez zmian.

## M4 (2026-10-29)

Kamienie pośrednie:

1. **K1**: `mcp-contracts` 4.0.0 (wektory, `dev-` w trybie dev, CC-137), `token-exchange` (OpenSearch), `service-account` (Service Desk),
   `422 system_not_configured` (CC-158), `subject_token_invalid`, `exchange_denied`.
2. **K2**: offboarding (`purge`, CC-155), czyszczenie nieużywanych połączeń (`unused_cleanup`), `provider_revoke_failed` przy usunięciu połączenia.
3. **K3**: limity `429` z `Retry-After` (OAuth start i complete na `sub`, CC-156; start rejestracji Authenticatora był już 10/h z M3), README,
   przegląd własny, obraz `mcp-credential-broker:m4-<sha>`.

Obraz: `mcp-credential-broker:m4-9fb07d2` (pierwotny, przed poprawkami przeglądu; aktualny: `mcp-credential-broker:m4-64aa705`, 377 testów; po poprawce `BffTokenVerifier` obraz `m4-e45669f`). Compose i stos nie ruszane.

| Wymaganie M4 | Stan |
| --- | --- |
| `mcp-contracts` 4.0.0 | `pom.xml`; wektory `jwt/` (64 przypadki, w tym `dev-kid-rejected-*` i `valid-dev-kid-in-dev-mode`), `audit-events/` (115, w tym cztery brokera z 4.0.0), `totp/`, `return-paths/` zielone |
| klucze `dev-` (CC-137) | `InternalJwtVerifier` odrzuca `kid` z prefiksem `dev-` z powodem `test_key_not_allowed`, chyba że `MCP_ALLOW_TEST_KEYS=true` **i** profil `devstack` (`Environment.acceptsProfiles`) |
| `token-exchange` OpenSearch (CC-157) | `SubjectTokenVerifier` (podpis, `iss`, `aud`, `exp` z skew 30 s, `sub` == `sub` wewnętrznego JWT) przed wymianą; `OpenSearchAdapter` (RFC 8693, `client_secret_basic`, `audience` i `scope` z konfiguracji); `expiresAt` zawsze, TTL <= 60 i <= do `expiresAt`; nic w OpenBao; zły token -> `400` + `subject_token_invalid`; odmowa IdP -> `403 exchange_denied` + audyt `exchange_denied`; IdP niedostępny, zły klient brokera, odpowiedź bez wartości -> `503` |
| `service-account` Service Desk (CC-157) | `GenericRestAdapter` + `ServiceAccountKeys`: `secret/data/mcp/service-accounts/<system>` (`value` albo `username`+`password` dla Basic, `expires_at`), `scheme` z konfiguracji systemu, `expiresAt` z rotacji albo `null`, bez cache w brokerze; `GET /v1/connections` go nie zwraca; brak / po terminie / zły wpis -> `503` |
| `422 system_not_configured` (CC-158) | `resolve`, `oauth/start`, `oauth/complete` (schemat `OAuthCompleteError`); audyt `credential_resolve` z powodem `system_not_configured`, outcome `error`, errorCode `internal_error`; identyfikator spoza kontraktów nadal `400` |
| `purge` (CC-155) | `POST /v1/admin/users/{sub}/purge`, CN `mcp-offboarding`, `204` idempotentne; połączenia (odwołanie u dostawcy, sekret ze wszystkimi wersjami, wiersz, `credential.invalidated`), `SecretStore.deleteAllOf` (wartości bez wiersza), przepływy OAuth, rejestracja Authenticatora z ziarnami i blokada; audyt `connection_change`/`user_purged` per połączenie, `authenticator`/`authenticator_removed`, `admin_change`/`user_purged` zawsze (także gdy nic nie było i dla nieznanego `sub`; `error` przy awarii) |
| czyszczenie nieużywanych | `OffboardingService.removeUnused` + `UnusedConnectionCleanupJob` (1 h), `broker.retention.unused-after` 180 dni, ponowny odczyt pod blokadą połączenia, audyt `unused_cleanup`; migracja V6 (indeks po ostatniej aktywności). "Oznaczenie wygasających": patrz Propozycje CC |
| limity `429` (CC-156, CC-151) | `RateLimiter` (Redis, stałe okno): `oauth/start` 10/min i `oauth/complete` 20/min na `sub` (konfiguracja), `Retry-After`, audyt `rate_limited`; start rejestracji Authenticatora 10/h już z M3 (`Retry-After` w teście) |
| nowe powody C8 | `provider_revoke_failed` (DELETE i purge), `authenticator_seed_missing` (z M3), `user_purged`, `unused_cleanup`, `subject_token_invalid`, `exchange_denied`, `system_not_configured`, `rate_limited`; każda linia w testach przechodzi schemat C8 |

### Dowody (K1-K3)

```
./mvnw -B verify
Tests run: 370, Failures: 0, Errors: 0, Skipped: 0   (BUILD SUCCESS, mcp-contracts 4.0.0; przed M4 było 328)
  TokenExchangeIntegrationTest 8, ServiceAccountIntegrationTest 6, ServiceAccountKeysTest 2, OffboardingIntegrationTest 6,
  RateLimitIntegrationTest 3, BrokerIntegrationTest 32, InternalJwtVectorTest 64, AuditEventVectorTest 115, ...
```

### Odstępstwa i decyzje M4

- **`provider_revoke_failed` obok, nie zamiast:** nieudane odwołanie tokenów daje osobną linię `connection_change` / `provider_revoke_failed` / `error` (bez `errorCode`, jak w
  wektorze), a zwykły wynik (`disconnected`, `user_purged`, `unused_cleanup`) idzie dalej jako `ok`. Przy zastąpieniu grantu (nowe połączenie) odwołanie nadal jest ciche (logowane).
- **Odmowa IdP vs błąd instalacji:** IdP dzieli kody błędów między "ten użytkownik nie może" i "broker źle skonfigurowany" (Keycloak: `invalid_request` dla audience, którego użytkownik
  nie dostaje, ale też dla literówki w `audience`). Odmową (`403`) są `access_denied`, `invalid_grant`, `invalid_target`, `invalid_request` (Keycloak mówi tak o audience, którego użytkownik nie dostaje) i `invalid_token`; `invalid_scope`
  (scope'y należą do klienta, nie do użytkownika), `invalid_client`, `unauthorized_client`, 5xx i nieznane kody to `503`. Każda odmowa: log `warn` z kodem i audience oraz licznik Micrometer `broker.token_exchange.denied{audience}` (endpoint `metrics` nie jest wystawiony: `management.endpoints.web.exposure` to tylko `health`). Skutek uboczny: zła nazwa `audience` w konfiguracji wygląda jak masowa odmowa (przyczyna w logu `warn` i w liczniku).
- **Broker nie cache'uje wymiany ani klucza konta:** kontrakt daje cache bramie (`cacheTtlSeconds`), a brak cache w brokerze oznacza, że rotacja w OpenBao i zmiana uprawnień w IdP działają od następnego `resolve`.
  Koszt: jedno wywołanie IdP albo OpenBao na `resolve` (gateway cache'uje do 60 s).
- **`azp` subjectToken nie jest ograniczane:** kontrakt wymaga `aud`, `exp`, `sub`; to, kto wymienił token, rozstrzyga IdP.
- **Konfiguracja typów:** `token-exchange` i `service-account` wykluczają inne typy w tym samym systemie (start się nie uda); adaptery `opensearch` i `generic-rest` są nazwane po roli, `SystemAdapter` (whoami) zostaje tylko dla typów z poświadczeniem użytkownika.
- **Purge a awarie:** kroki niezależne, `503` po wykonaniu wszystkich; połączenie, którego sekretu nie dało się skasować, zostaje w bazie (powtórzenie kończy). Wiersz Authenticatora jest usuwany przed ziarnami (osierocone ziarno sprząta `sweepOrphanSeeds`).
- **Limity OAuth:** wartości własne (kontrakt: konfiguracja brokera), okno stałe 1 min; licznik bez TTL (przerwany proces między `INCR` i `EXPIRE`) dostaje TTL przy pierwszym przekroczeniu zamiast blokować na zawsze.

### Poprawki po przeglądzie Opus (M1, L1-L8)

| # | Poprawka |
| --- | --- |
| M1 | `invalid_scope` -> `503`; `invalid_request` zostaje `403` (uzasadnienie w komentarzu `OpenSearchAdapter`); odmowy: `warn` + licznik `broker.token_exchange.denied`; testy `anInvalidScopeIsTheInstallationsFaultNotTheUsers` i log `warn` |
| L1 | `SubjectTokenVerifier`: `setAllowEmptyExpiryClaim(false)`, jawnie RS256; testy: token bez `exp`, `alg: none`, HS256 -> `400`. `BffTokenVerifier` poprawiony tak samo (wymagane `exp`, RS256; test `bffTokensWithoutExpOrWithAnotherAlgorithmAreRefused`: bez `exp`, `alg: none`, HS256, `typ` inny niż `JWT`/`at+jwt` -> `401`). Walidatory idą przez `JwtValidators.createDefaultWithValidators` (zostaje sprawdzenie odcisku certyfikatu), w obu weryfikatorach: `exp` wymagane, `typ`, `iss`, `aud`, a w BFF także `azp` i `sub` |
| L2 | Odpowiedź IdP odrzucana (`503`), gdy token równa się `subjectToken`, `issued_token_type` nie jest access tokenem, `token_type` nie jest `Bearer`/`N_A`, albo JWT nie ma `aud` z `token-exchange.audience` (token nieprzezroczysty: bez sprawdzenia `aud`) |
| L3 | `purge`: `findAll` w `attempt`, przepływy OAuth przed połączeniami; test z wstrzymanym PostgreSQL (sekret w OpenBao usunięty mimo `503`). Zostaje: gdy usunięcie połączenia zawiedzie na blokadzie, sekret idzie przez `deleteAllOf`, wiersz i `credential.invalidated` dopiero przy powtórzeniu (gateway cache <= 60 s, `resolve` daje `credential_required`) |
| L4 | `sub` ponad 255 znaków w `purge`: `204` bez działania (kontrakt zna tylko 204/403/503; żaden użytkownik takiego `sub` nie ma) i jedno `admin_change`/`user_purged`/`ok` bez `sub` |
| L5 | Czyszczenie pomija w danym przebiegu wiersze, które się nie udały (`offset`), do 50 partii; test z zajętą blokadą połączenia |
| L6 | `username` z `:` w koncie Basic -> `503`; README i Javadoc: `value` przy Basic to gotowe `base64(login:hasło)` |
| L7 | Brief ws-06, funkcje 3 i 7: **nie zrobione w M4**: opcjonalny nagłówek impersonacji konta serwisowego, limit `resolve` na `sub`, wykrywanie nietypowych wzorców (resolve wielu systemów naraz). Kontrakt 4.0.0 nie ma `429` w `resolve`; reszta wymaga decyzji |
| L8 | Awaria Redisa w limiterze: `RateLimitUnavailableException`, audyt `rate_limit_unavailable`, `503`; test z wstrzymanym Redisem |

### Przegląd własny M4

Sprawdzone ręcznie, bez zewnętrznego przeglądu (Opus i Haiku smoke zostają dla koordynatora): ścieżki, w których sekret mógłby wyjść poza `resolve` (logi i audyt: testy na całym wyjściu procesu, w tym token
subjectToken, token IdP, sekret klienta wymiany, klucz konta, ziarno TOTP); kolejność kontroli `purge` (CN przed wszystkim, bez tokenu); zgodność z ACL Redisa stosu (`INCR`, `EXPIRE`, `TTL`, `GETDEL`, `DEL`
są w `redis/broker.rules`); polityka OpenBao (`list` i `delete` na `secret/metadata/mcp/connections/*` już jest, odczyt `service-accounts/*` już jest).

### Czego broker potrzebuje od innych (M4)

**ws-01 (`mcp-platform-dev`), przed wdrożeniem obrazu `mcp-credential-broker:m4-<sha>`:**

1. Broker w compose: `SPRING_PROFILES_ACTIVE=devstack` razem z `MCP_ALLOW_TEST_KEYS=true`. Klucze generowane lokalnie przez stos mają `kid` z prefiksem `dev-` (CC-137), a broker 4.0.0 przyjmuje je tylko w trybie dev;
   bez tego `resolve` z takim kluczem kończy się `401 test_key_not_allowed`. Profil należy nadać w compose, nie w obrazie.
2. Systemy w brokerze (`BROKER_SYSTEMS_*`, obok istniejących `CONFLUENCE`/`GITLAB`):
   - OpenSearch: `BROKER_SYSTEMS_OPENSEARCH_BASEURL=http://opensearch.internal:8080` (wymagany przez schemat, nie jest wywoływany), `_ADAPTER=opensearch`, `_SUPPORTEDTYPES=token-exchange`, `_DEFAULTTYPE=token-exchange`,
     `_TOKENEXCHANGE_CLIENTID=mcp-credential-broker`, `_TOKENEXCHANGE_TOKENURL=http://keycloak:8080/realms/corp/protocol/openid-connect/token`, `_TOKENEXCHANGE_AUDIENCE=opensearch`,
     `_TOKENEXCHANGE_SCOPES=opensearch-audience`.
   - Service Desk: `BROKER_SYSTEMS_SERVICEDESK_BASEURL=http://servicedesk.internal:8080`, `_ADAPTER=generic-rest`, `_SUPPORTEDTYPES=service-account`, `_DEFAULTTYPE=service-account`, `_SECRETSCHEME=Bearer` (mock przyjmuje `Authorization: Bearer <klucz>`).
3. Keycloak: klient `mcp-credential-broker` (confidential, `standard.token.exchange.enabled`, opcjonalny scope `opensearch-audience`) już jest w `realm-corp.json`; nic do zmiany. Sprawdzić, że token `aud=mcp-credential-broker`
   wymieniony przez `mcp-gateway` ma `sub` równe `sub` tokenu klienta MCP (tak jest w opisie wymiany w `docs/uzytkownicy.md`).
4. OpenBao (`openbao/init.sh`): sekret klienta wymiany `secret/mcp/oauth-clients/opensearch` (`client_id=mcp-credential-broker`, `client_secret=$KC_CLIENT_MCP_CREDENTIAL_BROKER_SECRET`) i zmiana wiersza polityki
   `secret/data/mcp/oauth-clients/gitlab` na `secret/data/mcp/oauth-clients/*` (albo dopisanie `.../opensearch`); klucz konta serwisowego `secret/mcp/service-accounts/servicedesk` z `value=$SERVICEDESK_API_KEY`
   (polityka `service-accounts/*` już jest). Przykład:

   ```sh
   printf '%s' "$KC_CLIENT_MCP_CREDENTIAL_BROKER_SECRET" | bao kv put secret/mcp/oauth-clients/opensearch client_id=mcp-credential-broker client_secret=- >/dev/null
   printf '%s' "$SERVICEDESK_API_KEY" | bao kv put secret/mcp/service-accounts/servicedesk value=- >/dev/null
   ```
5. Certyfikat `mcp-offboarding` już jest w `certs/` (EKU clientAuth): offboarding wywołuje `POST https://mcp-credential-broker.internal:8443/v1/admin/users/{sub}/purge` bez tokenu, dwa razy
   (po IdP/IGA i po wylogowaniu back-channel) oraz purge gateway'a; oczekiwane `204`.
6. Redis i PostgreSQL: bez zmian (migracja V6 uruchamia się sama; ACL brokera ma już `INCR`, `EXPIRE`, `TTL`, `GETDEL`).
7. Gateway (ws-05): `credentialType` z konfiguracji dla `opensearch` (`token-exchange`) i `servicedesk` (`service-account`), `subjectToken` w `resolve` tylko dla `opensearch`; mapowanie `403 exchange_denied` na `access_denied` i `422 system_not_configured` na `internal_error`.

### Propozycje CC

Kontraktów nie zmieniam; propozycje do decyzji człowieka.

| # | Propozycja | Powód |
| --- | --- | --- |
| P1 | Opcjonalne pole `cleanupAt` (`Timestamp` albo `null`) w `Connection` (C4) i `GET /api/v1/connections` | Kontrakt mówi, że portal oznacza połączenia bliskie czyszczenia jako wygasające, ale retencja (180 dni) jest konfiguracją brokera; portal nie zna wartości i może liczyć tylko z własnej kopii. Broker nie zmienia statusu `expiring` (opis `ConnectionStatus` ogranicza go do `user-secret` z `expiresAt`) |
| P2 | Zamrozić w C4 pola wpisu `secret/data/mcp/service-accounts/<system>` (`value`, `username`, `password`, `expires_at`) i ścieżkę sekretu klienta wymiany (`secret/data/mcp/oauth-clients/<system>`, `client_secret`) | Kontrakt podaje tylko ścieżkę konta; nazwy pól wybrał broker, a zapisuje je ws-01 i operator. `value` przy Basic to `base64(login:hasło)`, `username` bez `:` (RFC 7617) |
| P3 | Opis `reason` dla `admin_change`: `user_purged` z wynikiem `error`, gdy `purge` się nie udał (dziś opis mówi tylko o `ok`) | Nieudany `purge` powinien zostawić ślad; broker emituje `admin_change` / `user_purged` / `error` / `upstream_unavailable` |
| P4 | `provider_revoke_failed`: napisać, że zdarzenie jest dodatkowe względem zdarzenia wyniku i nie ma `errorCode` | Wektor ma tylko jedno zdarzenie; broker emituje dwa (osobny wynik `ok` dla usunięcia) |
| P5 | Wskazać, które odpowiedzi IdP to `exchange_denied` (lista z "Odstępstw": `invalid_scope` to `503`), z logiem `warn` i licznikiem odmów | Granica użytkownik / konfiguracja jest dziś decyzją implementacji |

### Zostaje

- Wiersze `authenticator` w stanie `none` bez blokady i bez błędów (po `DELETE`/reset) nikt nie sprząta poza `purge` (nieszkodliwe: jeden wiersz na użytkownika).
- `sweepOrphanSeeds` przegląda cały prefiks `mcp/authenticators` bez stronicowania.
- Obraz nie był uruchomiony na stosie (zakaz zmian w compose); test akceptacyjny `make pat`/purge na prawdziwym stosie i Haiku smoke po stronie koordynatora i ws-01.
- Okno limitów OAuth jest stałe; przy rozproszeniu na wiele instancji liczy wspólny Redis, więc limit jest globalny na `sub`.

## M3 (2026-10-28), historia

Kamienie pośrednie:

1. **K1**: przejście na 3.0.1 (`identity_mismatch` nie istnieje w kodzie ani testach, `returnPath` bez zarezerwowanych
   prefiksów, CC-099), cały Authenticator: migracja V4, magazyn ziarna w OpenBao Transit, serwis, API C4 `/v1/authenticator*`
   i reset, audyt, wektory `totp/`.
2. **K2**: testy integracyjne po HTTP (rejestracja, równoległość, przechowywanie, macierz wywołujących), README.
3. **K3**: przegląd własny, STATUS, opis potrzeb wobec innych strumieni.

Obrazy: `mcp-credential-broker:m3-543403c` (K1), `m3-0252757` (K2), `m3-6203b4b` (K3; po nim tylko ta poprawka zdania). K4 (poprawki przeglądu, 3.0.2): `m3-<sha>` z komunikatu ostatniego commitu. Compose nie ruszany.

| Wymaganie M3 | Stan |
| --- | --- |
| mcp-contracts 3.0.1 | `pom.xml`; `identity_mismatch` nie występuje w kodzie ani testach (od M2 nie był zwracany; opis w README zostaje jako informacja); `ReturnPath` wg CC-099 (zarezerwowane prefiksy `/api`, `/s`, `/v`, `/.well-known`, segmenty `.`/`..`, bez `;`), wektory `return-paths/` (33) zielone |
| rejestracja (start, potwierdzenie, status, usunięcie) | tylko CN `mcp-portal-bff`; ziarno 20 bajtów `SecureRandom`, w `201` raz (`Cache-Control: no-store`, `Pragma: no-cache`), `otpauthUri` w stałej formie; rejestracja w toku zaszyfrowana, TTL 10 min, 3 próby, ponowny start zastępuje, `409 already_registered`, `429` po 10 startach na godzinę (wartość własna, kontrakt mówi tylko "limit brokera"); zadanie w tle kasuje ziarna niepotwierdzonych rejestracji |
| weryfikacja kodu | tylko CN `mcp-gateway`; RFC 6238, okno t-1..t+1, `lastAcceptedStep`, `replayed`, `burned`; zły format = 400 bez skutku |
| limity 5/15 min i 20/24 h | blokada 15 min jako własność użytkownika (przeżywa usunięcie, reset i nową rejestrację), `disabled` do ponownej rejestracji; aktywacja zeruje liczniki i `disabled` |
| atomowość na `sub` | wiersz `authenticator` z `select ... for update`; ziarno czytane przed blokadą i dopasowywane przez `registration_id`; testy: 50 równoległych błędnych kodów = 5 `invalid` + 45 `locked` (po HTTP, mTLS), dobowy limit dokładnie raz (jedno zdarzenie `authenticator_disabled`), ten sam kod w 20 żądaniach = jeden `ok` |
| `invalidate-codes` | tylko CN `mcp-gateway`, idempotentne, `burnedThrough`; `burned` nie liczy się do limitów (10 spalonych kodów pod rząd, brak blokady i brak wierszy błędów) |
| reset | `POST /v1/admin/users/{sub}/authenticator/reset`, CN `mcp-offboarding`, bez tokenu (token dołączony jest ignorowany); blokada zostaje |
| przechowywanie | Transit bez envelope, KV v2 `secret/data/mcp/authenticators/<sha256(sub)>` (aktywne) i `.../pending`, rekord z `sub` i rodzajem sprawdzany przy odczycie; baza tylko metadane; test: szyfrogram Alice pod ścieżką Mallory -> 503; ziarna nie ma w bazie, odpowiedziach poza `201` rejestracji ani w logach |
| audyt | `event: authenticator`, powody z kontraktu, każda linia walidowana schematem C8 w testach |
| wektory `totp/` | 44 scenariusze + RFC 6238 + `otpauth-uri` zielone (`TotpVectorTest`, 47 przypadków z testem sprzątania) |

### Dowody (K1-K3)

```
./mvnw -B verify
Tests run: 328, Failures: 0, Errors: 0, Skipped: 0   (BUILD SUCCESS, mcp-contracts 3.0.2; przed M3 było 199)
  TotpVectorTest 50, AuthenticatorIntegrationTest 18, InternalJwtVectorTest 61, AuditEventVectorTest 83, ...
```

### Przegląd M3 (Opus, 0 CRITICAL/HIGH/MEDIUM, 8 LOW): poprawki

| # | Znalezisko | Status |
| --- | --- | --- |
| 3.0.2 | czysty jar wektorów; wzorzec `backendUser` w C8 wyklucza `\p{Cc}`, `\p{Cf}`, `\p{Cs}` i kilka znaków niewidocznych | `pom.xml`, `AuditLog.validBackendUser` wg schematu (wektor `invalid-backend-user-zero-width` i 11 dodatkowych znaków w `AuditLogTest`); lista pomijanych wektorów usunięta |
| L1 | spójność OpenBao z bazą | zapis ziarna przed commitem zostaje (start: rezerwacja w bazie, potem zapis `pending`; potwierdzenie: zapis `active` przed transakcją), kasowanie po commicie (usunięcie, reset, `pending` po aktywacji), zadanie w tle sprząta wpisy bez wiersza po 15 min (`sweepOrphanSeeds`, kolumna `sub_hash`, migracja V5). Wiersz `active` bez ziarna: `503` raz, audyt `authenticator_seed_missing`, rejestracja wraca do `none` (bezpieczne, bo niezmiennik "active => ziarno istnieje" wynika z kolejności operacji; wariant ostrożniejszy, ręczne odzyskiwanie, zostawiałby użytkownika w `503` do `DELETE`). Testy: nieudane kasowanie przy usunięciu, sprzątanie z karencją, utrata ziarna |
| L2 | blokada wiersza przez wywołania OpenBao | brak wywołań OpenBao pod blokadą (zmiana kolejności jak wyżej), `lock_timeout` 2 s, poprawiony Javadoc i README; test równoległych zmian rejestracji i `verify` |
| L3 | parametry kontraktu konfigurowalne | okno, limity, blokada, TTL i liczba prób rejestracji to stałe (`AuthenticatorLimits`); w konfiguracji zostały tylko klucz Transit, prefiks, limit startów i interwały zadań |
| L4 | limit startów w stałym oknie | zostaje stałe okno 1 h, `429` ma `Retry-After` do końca okna (test) |
| L5 | audyt pustego usunięcia/resetu | linia `authenticator_removed` / `authenticator_reset_by_admin` tylko gdy coś istniało (test); `invalidate-codes` dla użytkownika bez rejestracji nadal bez linii (świadomie: nic się nie dzieje, `204`) |
| L6 | historia KV starego ziarna | przed zapisem nowego aktywnego ziarna `deleteActive` (wszystkie wersje) |
| L7 | `Locale` w `String.format` | `Locale.ROOT` w `Totp` i `AuthenticatorService` |
| L8 | luki testów | dopisane: `pending` pod ścieżką `active`, ziarno innej rejestracji tego samego użytkownika (nie jest usuwane: ziarno istnieje), wyścig zmian rejestracji z `verify`, nieudane kasowanie, sprzątanie, utrata ziarna, `Retry-After`, pusty audyt; start z `disabled` po HTTP już był w teście limitu dziennego |

Zostaje (świadomie): rzadki wyścig dwóch równoległych startów tego samego użytkownika może zostawić `pending` z ziarnem
pierwszego startu, wtedy `confirm` daje `enrollment_invalid` i użytkownik startuje ponownie. Sprzątanie wpisów przegląda
cały prefiks (`list`), co przy bardzo wielu użytkownikach trzeba będzie stronicować (M4). Polityka OpenBao dla `list` na
`secret/metadata/mcp/authenticators/*` jest już w zestawie dla ws-01.

### Odstępstwa i decyzje M3

- **Zakres:** brief przewiduje w M3 także `token-exchange` (OpenSearch) i `service-account`; zadanie tego etapu objęło tylko
  Authenticatora, więc oba typy są przeniesione poza M3 (README i `SystemRegistry` bez zmian).
- **Wektory w jarze 3.0.1** miały 49 nadmiarowych plików; 3.0.2 jest czysty, pomijanie w `Contracts.vectors` usunięte.
- **Zegar OpenBao:** `OpenBaoClient` dostaje `Clock.systemUTC()`, nie beana `Clock` aplikacji: dzierżawa tokenu biegnie
  w czasie rzeczywistym OpenBao, a `Clock` jest szwem testów biznesowych (wektory ustawiają go na daty z października).
- **Dwa wiersze na użytkownika w OpenBao**, a nie jeden: aktywne ziarno pod ścieżką z kontraktu, rejestracja w toku pod
  `.../pending`, żeby usunięcie jednego nie wymagało odczytu i zapisu drugiego (kontrakt wymaga ścieżki dla "aktywnego i w toku").
- **`authenticator_removed` także z brokera:** wektor kontraktu ma je z komponentu `portal`; broker zapisuje własną linię,
  bo tylko on wie, że usunięcie się udało.
- **Wiersz `authenticator` bez rejestracji** (stan `none`) istnieje, dopóki jest blokada lub wiersze błędów; nie ma
  jeszcze sprzątania takich wierszy (M4, razem z `purge`, który usunie wiersz razem z blokadą użytkownika).

### Czego broker potrzebuje od innych (M3)

**ws-01 (OpenBao w `mcp-platform-dev`, `openbao/init.sh`):**

```sh
bao read transit/keys/mcp-authenticators >/dev/null 2>&1 \
  || bao write -f transit/keys/mcp-authenticators type=aes256-gcm96
```

i w polityce `mcp-credential-broker` (obok dotychczasowych ścieżek):

```hcl
path "secret/data/mcp/authenticators/*"     { capabilities = ["create", "read", "update", "delete"] }
path "secret/metadata/mcp/authenticators/*" { capabilities = ["read", "list", "delete"] }
path "transit/encrypt/mcp-authenticators"   { capabilities = ["update"] }
path "transit/decrypt/mcp-authenticators"   { capabilities = ["update"] }
```

Do czasu zmiany start brokera działa, ale `POST /v1/authenticator/enrollment` i `verify` dają `503` (brak klucza i ścieżek).
Testy własne używają OpenBao w Testcontainers z tym samym kształtem (`TestEnvironment.configureOpenBao`). Klucz mógłby
też wykorzystać istniejący `mcp-credential-broker` (`BROKER_AUTHENTICATOR_TRANSITKEY`), ale osobny klucz pozwala go
rotować i odwołać niezależnie od poświadczeń; rekomenduję osobny.

**ws-05 (gateway):** wywołania `GET /v1/authenticator`, `verify`, `invalidate-codes` muszą nieść wewnętrzny JWT, wariant
użytkownika, z `tool` (bez `tool` broker odpowiada `401`, wariant serwisowy też `401`) i `X-Request-Id` równym `rid`. Każdy
status inny niż 200 (verify) lub 204 (invalidate) to odmowa po stronie gateway'a. `locked` niesie `retryAfterSeconds` >= 1.

**ws-07 (BFF):** tokeny po token exchange jak dla połączeń; nazwa użytkownika w `otpauthUri` pochodzi z claimu
`preferred_username` tokenu. Broker nie sprawdza świeżości MFA (kontrakt), więc step-up przed `POST enrollment` i
`DELETE` jest wyłącznie po stronie BFF. Reset przez helpdesk wymaga klienta z certyfikatem CN `mcp-offboarding`.

## M2 (2026-10-28)

Kamienie pośrednie (wszystkie w jednym commicie kodu, bo `CredentialService` zależy od `OAuthService`; testy
zielone dopiero po całości):

1. kontrakty 2.2.3 + whoami bez porównania tożsamości + `expiresAt` bez walidacji + whoami GitLaba dla PAT;
2. `oauth/start` i `oauth/complete`: przepływy w Redisie, wymiana kodu, tożsamość, zapis w OpenBao;
3. odświeżanie (przy `resolve` i w tle), blokada, odwołany grant -> `revoked`, odwołanie u dostawcy przy `DELETE`;
4. dane dla katalogu (`listSystems`/`listConnections` dla `user-oauth`), README, test na żywym stosie (host).

| Wymaganie M2 | Stan |
| --- | --- |
| mcp-contracts 2.2.5 | `pom.xml` (2.2.3 usunęło porównanie tożsamości, 2.2.5 dodało `backendUser` w C8); wszystkie wektory C2 (55) i C8 (42) zielone; wektory `whoami-identity/` wycofane w 2.2.3, test `IdentityRuleVectorTest` i klasa `IdentityRule` usunięte |
| `startOAuth` / `completeOAuth` | tylko CN `mcp-portal-bff` + token użytkownika; `sub` z tokenu; PKCE S256, `state` 32 bajty, `flowId` w Redisie 10 min, GETDEL; `returnPath` walidowany (CC-032), nie przechowywany |
| `state` jednorazowy i związany z użytkownikiem | cudzy `sub` -> `422 flow_invalid` bez zużycia przepływu właściciela; zły `state`, ponowne użycie, wygasły przepływ, wcześniejszy `start` tego samego użytkownika -> `flow_invalid`. Związanie z **sesją** przeglądarki jest po stronie BFF (broker nie widzi sesji): patrz "Co musi wiedzieć ws-07" |
| wymiana kodu, konto | whoami GitLaba (`/api/v4/user`, `username`) daje `backendUser`; bez porównania z SSO (CC-101), `identity_mismatch` nie jest zwracane; błąd po wymianie kodu bez zapisu -> tokeny odwołane u dostawcy; `invalid_grant` -> `flow_invalid`; 5xx/timeout/`invalid_client` -> `503` |
| tokeny w OpenBao | access + refresh razem, Transit + KV v2 jak PAT, nowa wersja przy każdym odnowieniu, stara usuwana po przełączeniu wiersza |
| odświeżanie | przy `resolve` (margines 2 min > `cacheTtlSeconds`) i zadaniem w tle (okno 5 min, co minutę); blokada Redis `SET NX PX` z właścicielem; rotacja refresh tokenu; `invalid_grant` -> `revoked` + `credential.invalidated` + `resolve` 409 |
| `ConnectErrorCode` / `cancelled` (CC-086) | po stronie BFF; broker zwraca `flow_invalid` (422) albo `503` (od 2.2.3 bez `identity_mismatch`); patrz "Propozycje CC" |
| PAT (`PUT secret`, CC-090/CC-084) | bez porównania tożsamości (CC-101): whoami tylko dla ważności (`422 secret_invalid`) i `backendUser`; whoami Jira/Confluence/GitLab wg tabeli; `expiresAt` opcjonalny i bez walidacji (przeszłość daje `expired`); `expiring` tylko przy podanej dacie |
| `backendUser` w audycie (CC-117, 2.2.5) | zdarzenie `connection_change` niesie `backendUser` (login z whoami) przy zapisie PAT, połączeniu OAuth, odświeżeniu tokenu (z zapisanego wiersza, bez whoami: odświeżanie nie zmienia konta) i rozłączeniu (z wiersza, jeśli jest). Pole jest ustawiane od razu po whoami, więc zdarzenie błędu zapisu (503) też je ma. Wartość poza wzorcem schematu (1..255 znaków, bez znaków sterujących, DEL, U+2028/2029, bidi) albo z niesparowanym surogatem jest pomijana, a w logu aplikacji ląduje ostrzeżenie bez wartości (świadoma decyzja: połączenie mimo to powstaje, patrz README). Zdarzenie `authentication` pola nie dostaje. Testy: `AuditEventVectorTest`, `AuditLogTest`, `CredentialServiceTest`, test integracyjny "mallory" (PAT konta mallory podpięty przez alice: `sub` alice, `backendUser` mallory; walidacja schematem każdego zdarzenia, brak sekretów w logu) |
| `X-Request-Id` | na każdej odpowiedzi (test na wszystkich odpowiedziach obu klas integracyjnych) |
| dane dla katalogu (CC-080) | `GET /v1/systems`: `supportedTypes`, `defaultType`, `oauthScopes` (pusta lista zamiast `[""]`, poprawka błędu z M1); `GET /v1/connections`: `type`, `status`, `backendUser`, `lastUsedAt`; dla `user-oauth` `expiresAt` = `null` |
| niezmienniki | `resolve` tylko CN `mcp-gateway`; portal tylko dla `sub` z tokenu (test: `flowId`/`sub` obcego użytkownika); żadna odpowiedź poza `resolve` nie zawiera tokenu/PAT/`client_secret` (`@AfterAll` obu klas na wszystkich zarejestrowanych odpowiedziach); brak tokenów, kodu, verifiera, `state`, `client_secret` w logach (grep na `CapturedOutput` w testach OAuth) |

### Dowody

```
./mvnw -B verify          (stan po poprawkach przeglądu M2)
Tests run: 199, Failures: 0, Errors: 0, Skipped: 0   (BUILD SUCCESS, mcp-contracts 2.2.5; przed CC-117 było 147)
  OAuthIntegrationTest 31, BrokerIntegrationTest 31, InternalJwtVectorTest 55, AuditEventVectorTest 47, AuditLogTest 5,
  OAuthRefreshFailureIntegrationTest 4, CredentialServiceTest 9, OperationsContractTest 3, OpenBaoClientTest 3,
  OAuthClientSecretsTest 2, KeySourceTest 3, ...
```

Test na żywym stosie (stan sprzed CC-101: wiersze z `identity_mismatch` poniżej dziś kończą się `200`; broker jako proces hosta na `https://localhost:18710`, prawdziwy Keycloak z token
exchange `aud=mcp-credential-broker`/`azp=mcp-portal-bff`, OpenBao z AppRole i Redis z ACL `broker` ze stosu
M1 przez `scripts/run-dev-host.sh`; GitLab jako WireMock standalone na 18711; własny PostgreSQL w kontenerze
`ws06-pg` na 18719, usunięty po teście: broker z V3 nie powinien dzielić bazy z brokerem ze stosu, patrz L11 niżej).
Wynik:

```
start            200  authorizeUrl .../oauth/authorize?client_id=mcp-broker&response_type=code&redirect_uri=...&state=...&code_challenge=...&code_challenge_method=S256&scope=read_api
complete         200  {"status":"connected","backendUser":"alice"}
complete (again) 422  {"error":"flow_invalid"}
complete (code of bob, flow of alice)  422 {"error":"identity_mismatch"}   (oba tokeny boba odwołane w GitLabie)
complete (bob with alice's flow)       422 {"error":"flow_invalid"}
PUT secret gitlab (PAT alice)          200 connected;  z expiresAt 2020-01-01 -> 200 expired
DELETE gitlab    204, GET /v1/connections -> []
```

W logu brokera 0 wystąpień tokenów, kodu i `client_secret`. Polityka OpenBao i ACL Redisa ze stosu M1 wystarczają
(użyte komendy: GET, SET z TTL, GETDEL, DEL, SET NX); nic w `mcp-platform-dev` nie było zmieniane.

### Definition of Done (punkty OAuth)

| Punkt | Test |
| --- | --- |
| link A otwarty przez B -> `flow_invalid`/`identity_mismatch`, token B nie trafia do A | `anotherUsersFlowIsRefusedWithoutBurningIt` (obcy `sub`: kod B nigdy nie wymieniony, u B i A brak wiersza, A kończy po tym przepływ), `aCodeOfAnotherAccountIsAnIdentityMismatchAndNothingIsStored` (brak wiersza i wpisu w OpenBao, `resolve` 409, tokeny odwołane), `identityMismatchKeepsTheExistingConnection` |
| `state` jednorazowy | `aStateWorksOnce`, `aWrongStateIsRefusedAndTheOwnersFlowSurvivesIt`, `aNewStartReplacesThePendingFlowOfTheSameUser`, `anExpiredFlowIsInvalid` |
| błąd dostawcy, timeout | `providerFailuresAreRefusedAndNothingIsStored` (500, `invalid_grant`, `invalid_client`, opóźnienie 2,5 s przy timeoucie 1 s) |
| refresh token unieważniony u dostawcy -> `revoked`, `resolve` -> `credential_required` | `aRefreshTokenRevokedAtTheProviderMakesTheConnectionRevoked`, `theSweepMarksARevokedGrantWithoutAResolve` |
| po `DELETE` publikowane `credential.invalidated`, odwołanie u dostawcy | `disconnectingRevokesTheTokensAtTheProvider`, `disconnectingWorksWhenTheProviderIsDown` |
| rotacja refresh tokenu, brak podwójnego zużycia | `anAccessTokenNearExpiryIsRenewedOnResolve`, `parallelResolvesRenewOnce` (6 równoległych `resolve`, jedno odnowienie) |
| PAT z innym loginem -> zapisany, `backendUser` = konto z whoami (CC-101); PAT odrzucony przez system -> `secret_invalid`, nic nie zapisane | `gitLabPersonalAccessTokenIsStoredWithItsAccount`, `aPatOfAnotherLoginIsStoredAndShownAsThatAccount`, `aPatTheSystemRefusesIsNotStored` |

Punkty M3-M4 (purge, przypomnienia, rate limit, token-exchange, service-account) dalej poza zakresem.

### Decyzje i odstępstwa M2

- **Przepływy w Redisie, nie w PostgreSQL:** GETDEL daje atomowe zużycie, TTL czyści resztki. Redis przechowuje
  `code_verifier` jawnie (do 10 min); bez kodu autoryzacji, który trafia tylko do przeglądarki użytkownika i
  callbacku BFF, jest bezużyteczny. Klucze pod `broker:oauth:` (prefiks ACL `broker:*`).
- **`client_secret` OAuth z OpenBao** (po przeglądzie; w pierwszej wersji M2 z zmiennej środowiska):
  `secret/mcp/oauth-clients/<system>`, pole `client_secret`, odczyt przez AppRole brokera (ws-01 dodał wpis i
  politykę w M2.3), cache w pamięci 5 min. Wartość z konfiguracji (`...OAUTH_CLIENTSECRET`) jest zapasem tylko
  gdy `broker.allow-plain-http=true`; poza dev jej ustawienie przerywa start.
- **Brak lokalnego `returnPath`:** broker waliduje go i nie zapisuje; C4 nie zwraca go w `complete`, więc BFF
  trzyma go sam.
- **GitLab tylko jako system `user-oauth`:** "Jira mock" z briefu (OAuth do Jiry) nie powstał; w M2 Jira zostaje
  przy PAT (decyzja człowieka: "Połącz przez OAuth" = GitLab, "Dodaj PAT" = Jira). Konfiguracja GitLaba przez
  zmienne środowiskowe (README), nie w `application.yml`, żeby start nie wymagał adresu GitLaba.
- **Odwołanie u dostawcy** (`DELETE`, błędy po wymianie kodu) zrobione w M2, choć brief liczy revoke do M4: bez niego
  zostawałyby żywe granty w GitLabie. Pozostałe elementy M4 (purge, przypomnienia, rate limit) nie ruszone.
- **Kamienie w jednym commicie kodu** (kolejność w tabeli powyżej odpowiada kolejności prac, nie commitom).

## Przegląd M2 (2026-10-28): znaleziska i poprawki

Recenzja: `review-broker-M2.md` (0 CRITICAL, 1 HIGH, 4 MEDIUM, 12 LOW). Poprawki w commitach po `8e7f037`.

| # | Znalezisko | Status | Co zrobione / uwagi |
| --- | --- | --- | --- |
| H1 | odświeżanie w toku wskrzesza połączenie po `DELETE` | naprawione | zapis odświeżenia warunkowy: `update ... where secret_version = :odczytana and state = 'connected'` (`ConnectionRepository.switchSecretVersion`); 0 wierszy -> nowy sekret usunięty, nowe tokeny odwołane u dostawcy, `resolve` -> 409. `markRevoked` z tym samym warunkiem. `DELETE`, `oauth/complete` i `PUT secret` biorą tę samą blokadę (sub, system) co odświeżanie (`OAuthService.underRefreshLock`; `503` gdy nie da się jej wziąć w `refresh-lock-wait`). Testy: `aDisconnectDuringARefreshWaitsForItAndThenWins`, `aRefreshThatLostItsLockCannotBringADisconnectedConnectionBack` (blokada skasowana w trakcie = wygasła dzierżawa; PoC recenzenta przeniesiony jako test) |
| M1 | blokada bez właściciela i bez gwarancji czasu | naprawione (z zastrzeżeniem) | wartość blokady losowa, zwolnienie tylko przez właściciela; dzierżawa 60 s (`broker.oauth-flow.refresh-lock-lease`) przy limicie odpowiedzi dostawcy = `timeout` systemu (domyślnie 5 s, M3) i zapisie z 2 ponowieniami; termin sprawdzany ponownie pod blokadą (było). Zwolnienie to `GET` + `DEL`, nie skrypt: ACL Redisa brokera nie ma `EVAL` (propozycja 5). Zapis warunkowy z H1 jest fencingiem. Test `aLockIsReleasedOnlyByItsOwner` |
| M2 | utrata rotowanego refresh tokenu po błędzie zapisu | naprawione | zapis nowego sekretu i przełączenie wiersza ponawiane (2 razy, 200 i 600 ms); jeśli i to zawiedzie po rotacji, nowe tokeny są odwoływane u dostawcy, a połączenie dostaje stan `error` (audyt `refresh_token_lost`), nie `revoked`; `revoked` tylko po `invalid_grant` od dostawcy. Zadanie w tle przerywa przebieg przy pierwszej awarii OpenBao/Redisa/bazy i pomija dalsze wiersze systemu, którego dostawca zawiódł. Odczyt `client_secret` z OpenBao następuje przed wywołaniem dostawcy. Testy: `OAuthRefreshFailureIntegrationTest` (przejściowa awaria, utrata tokenu, przerwanie zadania) |
| M3 | brak limitu rozmiaru i czasu ciała odpowiedzi dostawcy | naprawione | `UpstreamHttp`: własny `BodySubscriber` z limitem 64 KB i termin całej odpowiedzi (nagłówki + ciało) równy `timeout` systemu, `sendAsync` + `get(timeout)` + `cancel`. Testy: `anOversizedProviderAnswerIsRefusedAsUnavailable`, `aProviderThatTricklesItsAnswerIsCutOffAtTheTimeout`. Dotyczy GitLaba; `AtlassianDcAdapter`, `OpenBaoClient` i pobieranie JWKS mają własny `BodyHandlers.ofByteArray()` bez limitu (nie ruszone: poza zakresem poprawki, odnotowane) |
| M4 | whoami po nazwie, nie po niezmiennym id | bez przedmiotu | CC-101: nie ma porównania, więc ryzyko podszycia się pod nazwę znika; zostaje ryzyko rezydualne CC-090 (użytkownik może podpiąć PAT dowolnego konta, do którego ma poświadczenie), przyjęte przez człowieka |
| L1 | zły `state` spala przepływ właściciela | naprawione | `state` i system porównywane na wyniku `peek`, `take` dopiero po zgodności; test `aWrongStateIsRefusedAndTheOwnersFlowSurvivesIt` |
| L2 | tokeny nieodwołane po błędach po wymianie kodu | naprawione | `finally` w `complete`: każda droga bez zapisu odwołuje access i refresh token (whoami `Rejected`/błąd, błąd zapisu, `identity_mismatch`); test `tokensIssuedForACodeAreRevokedWhenTheIdentityCheckCannotBeDone` |
| L3 | małe litery poza ASCII łączą znaki (KELVIN SIGN) | bez przedmiotu | najpierw wdrożona reguła z 2.2.2 (CC-100, ASCII bez wielkości liter, inaczej NFC i `equals`, przechodziła 20 wektorów), potem decyzja człowieka (CC-101, 2.2.3) usunęła porównanie tożsamości w ogóle; `IdentityRule` usunięte |
| L4 | `complete` zastępujące połączenie nie odwołuje starego grantu | naprawione | stare tokeny odwoływane po przełączeniu wiersza (także gdy `PUT secret` zastępuje `user-oauth`); testy `connectingAgainRevokesTheGrantItReplaces`, `storingAPatOverAnOAuthConnectionRevokesTheGrant` |
| L5 | zadanie w tle odświeża z `force` | naprawione | brak `force`: pod blokadą sprawdzane "wygasa przed now + okno" (margines dla `resolve`, `sweep-window` dla zadania) |
| L6 | zadanie w tle może głodzić połączenia | częściowo | zapytanie bierze tylko systemy skonfigurowane z OAuth; po awarii dostawcy reszta wierszy tego systemu jest pomijana w przebiegu. Wiersze, które zawodzą trwale z innych powodów, nadal zajmują miejsce w paczce 100 (stan `error`/`next_attempt_at` wymagałby migracji; M4) |
| L7 | nieudane odwołanie u dostawcy tylko w logu | opisane | audyt `disconnected` nadal bez śladu nieudanego odwołania; kolejka ponowień i powód `provider_revoke_failed` w M4 |
| L8 | `completeOAuth` zwraca 400 spoza kontraktu | opisane | propozycja CC 3 (bez zmian) |
| L9 | `client_secret` w zmiennej środowiska | naprawione (zadanie 4) | OpenBao, patrz decyzje; zapas z konfiguracji tylko w dev |
| L10 | `portalBaseUrl` bez wymogu https | naprawione | `requireTls` także dla `broker.portal-base-url` (bez `allow-plain-http` start przerwany). Bez osobnego testu: wymóg jest w beanie `systemRegistry`, `requireTls` ma test |
| L11 | opis migracji V3 w STATUS nieprecyzyjny | poprawione | sprawdzone doświadczalnie (Flyway z V1-V2 na bazie po V3): domyślnie ignoruje migracje "z przyszłości", stary obraz **startuje** (`current=3`). Realny problem wspólnej bazy to funkcjonalny: stary obraz obsłuży wiersze `user-oauth` bez odświeżania i bez odwołania u dostawcy, a jego `PUT secret` na takim wierszu zostawi stare `access_expires_at`. Dlatego jedna wersja brokera na bazę (ws-01 przebudowuje obraz), a skrypt hosta używa własnej bazy |
| L12 | luki testów | częściowo | dopisane: H1, M1, M2, M3, M18 (`parallelResolvesRenewOnce` sprawdza, że nowy refresh token nie został użyty). Zostaje M10 (przepływ jednego systemu nie kończy drugiego): wymaga dwóch systemów OAuth, dziś jest jeden; sprawdzenie w kodzie jest, test na poziomie serwisu przy drugim systemie |

Smoke Haiku (FAIL: `run-dev-host.sh` łączył się z bazą współdzieloną, port 18100 zajęty, ścieżka `../mcp-platform-dev`): skrypt
startuje własny PostgreSQL (`mcp-broker-host-pg-18711`, usuwany przy wyjściu) albo używa `MCP_DB_URL`, słucha na
18710 (zajęty port -> komunikat), `MCP_PLATFORM_DEV` z czytelnym błędem, sprawdza wersję JDK. Sprawdzone według README w
`git clone` (`scratchpad/broker-fix-check`): start z `Successfully applied 3 migrations`, `/actuator/health` z certyfikatem
klienta -> `UP`, `resolve` bez certyfikatu -> zerwany handshake (kod 000), po zatrzymaniu brak procesów i kontenerów.

Tożsamość: decyzja człowieka z 2026-10-28 w dwóch krokach. Najpierw reguła ASCII/NFC (2.2.2, CC-100), potem, ze względu na różne
loginy tej samej osoby w różnych systemach, brak porównania w ogóle (2.2.3, CC-101). Broker jest na 2.2.5: whoami daje ważność
(`secret_invalid`) i `backendUser` (zapisany, zwracany w `GET /v1/connections`, `PUT secret`, `oauth/complete`).
Konfiguracja `identity-claim` usunięta. Zależności `BackendIdentity.email` (GitLab/Jira) pozostają w adapterach, bez użycia.

**Audyt a `backendUser`:** od 2.2.5 (CC-117, propozycja 7 niżej przyjęta) zdarzenie `connection_change` niesie
`backendUser`; szczegóły w tabeli M2 wyżej.

## Propozycje CC (dla ws-00, nie wpisane do `mcp-contracts`)

1. **`oauth/complete`: błędy dostawcy.** `OAuthCompleteError` ma `flow_invalid` (i wycofane `identity_mismatch`). Broker
   zwraca `422 flow_invalid` dla `invalid_grant` (kod użyty/wygasły/zły verifier) i `503 upstream_unavailable` dla
   awarii, timeoutu i odrzucenia klienta (`invalid_client`). Proponuję dopisać do opisu `completeOAuth`, że BFF
   mapuje `503` na `provider_error` (patch, tylko opis), albo dodać `provider_error` do enum (minor).
2. **`Connection.expiresAt` dla `user-oauth`.** Broker zwraca `null` (access token odnawia się sam), a przykład
   `two_connections` w C4 pokazuje `gitlab` z `status: expiring` i datą. Proponuję poprawić przykład (patch) i dopisać
   w opisie `Connection`, że `expiring`/`expiresAt` dotyczą tylko `user-secret`.
3. **`400` dla systemu bez `user-oauth`** w `startOAuth`/`completeOAuth` (analogicznie do `putSecret` bez
   `user-secret` z M1): dopisać odpowiedź `400` z `BadRequest` do obu operacji (dziś `startOAuth` ją ma,
   `completeOAuth` nie).
4. **Lokalizacja `client_secret`** klienta OAuth w OpenBao: wpis do D6 (ścieżka `secret/data/mcp/oauth-clients/<system>`,
   pole `client_secret`). Polityka AppRole już ją ma (ws-01).
5. **Blokada odświeżania bez skryptów Redis.** ACL `broker` w `mcp-platform-dev` nie ma `EVAL`/`EVALSHA`, więc zwolnienie
   blokady to `GET` + `DEL` (dwa polecenia). Skutek jest ograniczony zapisem warunkowym w bazie (patrz H1/M1), ale
   atomowe compare-and-delete wymaga `+eval +evalsha` dla `~broker:*` w ACL `broker` (prośba do ws-01, nie CC).
6. **(zamknięta przez CC-101)** warunek wdrożenia reguły C4.1 nie jest już potrzebny.
7. **`backendUser` w audycie C8.** Przy braku porównania tożsamości ślad "kto podpiął które konto" jest jedyną kontrolą
   po fakcie, a `audit-event.schema.json` nie ma na to pola (`additionalProperties: false`). Proponuję opcjonalne pole
   `backendUser` (string, <= 255, ta sama ochrona znaków co `username`) w zdarzeniu `connection_change` brokera (minor).

## Czego broker potrzebuje od innych

**ws-01 (mock GitLaba jako dostawca OAuth w `mcp-platform-dev`):**

- adres dla przeglądarki (osobny od adresu sieci compose), np. `http://localhost:<port>/oauth/authorize`, i adres dla
  brokera w sieci `mcp-dev-core`, np. `http://gitlab.internal:8080`; broker dostaje oba:
  `BROKER_SYSTEMS_GITLAB_BASEURL` i `BROKER_SYSTEMS_GITLAB_OAUTH_AUTHORIZEURL` (reszta zmiennych w README);
- `client_id` (proponuję `mcp-broker`, jak w przykładzie C4) i `client_secret` w `.secrets` (broker:
  `BROKER_SYSTEMS_GITLAB_OAUTH_CLIENTSECRET`), redirect URI klienta = `${MCP_PORTAL_URL}/api/v1/oauth/callback`
  (jedna domena, CC-089);
- endpointy: `GET /oauth/authorize` (zalogowanie jako wybrany użytkownik, powrót z `code` i `state`; ścieżka
  `error=access_denied` dla "Anuluj"), `POST /oauth/token` (`authorization_code` z weryfikacją PKCE S256 i
  `client_secret` w ciele; `refresh_token` z rotacją; `invalid_grant` dla użytego/obcego), `POST /oauth/revoke`,
  `GET /api/v4/user` (Bearer: token OAuth lub PAT; `username` = login użytkownika, który się zalogował w mocku);
  możliwość zalogowania w mocku jako inna osoba niż użytkownik portalu (demo: konto o innym loginie pokazane jako `backendUser`);
  konfigurowalne `expires_in` (domyślnie 7200, do demonstracji odświeżenia np. 60 s);
- zmiany w compose brokera: obraz przebudowany na tym repo (migracja V3 w bazie `broker`), `MCP_PORTAL_URL` =
  publiczny adres portalu, zmienne GitLaba. Polityka OpenBao i ACL Redisa bez zmian.

**ws-07 (BFF) - co musi wiedzieć o przepływie OAuth:**

- po `start` BFF zapisuje w sesji `flowId`, wartość `state` (parametr w `authorizeUrl`) i `returnPath`; w callbacku
  szuka po `state` w sesji bieżącego użytkownika i **sam** odrzuca (`flow_invalid`), gdy przepływu w tej sesji nie ma.
  To jest związanie z sesją; broker wiąże z `sub` i `state`. `GET /api/v1/oauth/callback?error=access_denied`
  -> `connectError=cancelled` bez wołania brokera; inny `error` -> `provider_error`;
- `complete` dostaje `flowId`, `code`, `state` z callbacku; odpowiedź `422 flow_invalid` -> ten sam
  kody `connectError`; `503` i inne błędy brokera -> `provider_error`; sukces -> `connected=<system>`;
- `code` i `state` nie mogą trafić do logów BFF ani do nagłówka `Referer` (callback ma je w query); przepływ jest
  jednorazowy, więc powtórzenie callbacku (odświeżenie strony) da `flow_invalid`;
- token do brokera: jak przy `PUT secret` (`aud=mcp-credential-broker`, `azp=mcp-portal-bff`), `sub` zawsze z tokenu;
  `X-Request-Id` jest przyjmowany i zwracany;
- w katalogu: `credential.oauthScopes` z `GET /v1/systems`; `connection.expiresAt` jest `null` dla `user-oauth`, status
  `revoked` po odwołaniu grantu u dostawcy (akcja "Połącz ponownie"); PAT do GitLaba idzie tym samym `PUT secret`,
  bez porównania tożsamości, `backendUser` z whoami (CC-101);
- kolejny `start` tego samego użytkownika dla tego samego systemu unieważnia poprzedni link (dwie karty: wygrywa
  ostatnia); przepływ wygasa po 10 min.

## Otwarte po M2

- Rate limit `start`/`complete` per `sub` (M4); dziś ogranicza jeden aktywny przepływ na (użytkownik, system).
- Atomowe zwolnienie blokady odświeżania skryptem (ACL Redisa), patrz propozycja 5.
- Brak testu na prawdziwym GitLabie; mock od ws-01 jeszcze nie istnieje (testy na WireMock).

## M1: zrobione

Sekcje M1 i przeglądu M1 poniżej opisują stan z 2026-10-27; reguła tożsamości (`identity_mismatch`, `identity-claim`, `email_verified`) została usunięta w CC-101.

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
