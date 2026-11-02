# mcp-credential-broker

Credential broker platformy MCP (strumień ws-06): jedyne miejsce, w którym leżą poświadczenia użytkowników
do systemów docelowych, per (`sub`, system). Gateway pobiera z niego poświadczenie przy wywołaniu
narzędzia (`resolve`), portal BFF zapisuje je w imieniu zalogowanego użytkownika. Kontrakt: C4 z
`mcp-contracts` 5.1.0 (`openapi/credential-broker.v1.yaml`), audyt C8, zdarzenie C4.3.

Stan: kamień M5, kod gotowy do dowodu z runnera CI (kontrakty 5.1.0, praca w kilku instancjach na jednej bazie, fail-closed bez Redisa, OpenBao i PostgreSQL, `ci/run.sh`; poza tym wszystkie cztery typy poświadczeń, offboarding, limity z M4, Authenticator TOTP z M3, PAT i "Połącz przez OAuth" z M1-M2). Co działa, czego jeszcze nie ma i odstępstwa od briefu: [STATUS.md](STATUS.md).

## API w tej wersji

Wszystko po HTTPS z wymaganym certyfikatem klienta z wewnętrznego CA (port 8443 w kontenerze).

| Operacja | CN certyfikatu | Token | Wynik |
| --- | --- | --- | --- |
| `POST /v1/credentials/resolve` | `mcp-gateway` | wewnętrzny JWT C2, wariant użytkownika, `aud=mcp-credential-broker` | `200 {scheme, value, type, expiresAt, cacheTtlSeconds}` z `Cache-Control: no-store`, `409 credential_required`, `403 exchange_denied`, `422 system_not_configured`, `400` (także zły `subjectToken`) |
| `PUT /v1/connections/{system}/secret` | `mcp-portal-bff` | token użytkownika po token exchange: `aud` zawiera `mcp-credential-broker`, `azp=mcp-portal-bff` | `200 {status, backendUser, expiresAt}`, `422 secret_invalid` |
| `GET /v1/systems` | `mcp-gateway`, `mcp-portal-bff` | jak wyżej; od gateway'a także wariant serwisowy C2 (CC-030) | lista systemów z konfiguracji |
| `GET /v1/connections` | `mcp-portal-bff` | token użytkownika jak przy `PUT secret` | połączenia użytkownika z tokenu, statusy C4, bez wartości sekretu |
| `DELETE /v1/connections/{system}` | `mcp-portal-bff` | jak wyżej | `204`; usuwa sekret (wszystkie wersje KV) i metadane, publikuje `credential.invalidated`; idempotentne |
| `POST /v1/connections/{system}/oauth/start` | `mcp-portal-bff` | jak wyżej | `200 {authorizeUrl, flowId}`; `400` dla złego `returnPath` albo systemu bez `user-oauth`, `422 system_not_configured`, `429 rate_limited` |
| `POST /v1/connections/{system}/oauth/complete` | `mcp-portal-bff` | jak wyżej | `200 {status, backendUser}`, `422 flow_invalid` albo `system_not_configured`, `429 rate_limited`, `503` przy awarii dostawcy |
| `GET /v1/authenticator` | `mcp-portal-bff`, `mcp-gateway` | token użytkownika; od gateway'a wewnętrzny JWT z `tool` | `200 {state, registeredAt, lastUsedAt, lockedUntil, disabledAt, disabledReason}`, bez ziarna |
| `DELETE /v1/authenticator` | `mcp-portal-bff` | token użytkownika | `204`, idempotentne; usuwa ziarno (aktywne i w toku), nie zdejmuje blokady |
| `POST /v1/authenticator/enrollment` | `mcp-portal-bff` | token użytkownika | `201 {enrollmentId, otpauthUri, secret, expiresAt}` z `no-store` (jedyny wyjątek poza `resolve`), `409 already_registered`, `429 rate_limited` |
| `POST /v1/authenticator/enrollment/confirm` | `mcp-portal-bff` | jak wyżej | `200` status `active`, `422 invalid_code` albo `enrollment_invalid` |
| `POST /v1/authenticator/verify` | `mcp-gateway` | wewnętrzny JWT z `tool` | `200 {result[, retryAfterSeconds]}`: `ok`, `invalid`, `replayed`, `burned`, `locked`, `disabled`, `not_registered`; `400` dla kodu spoza `^[0-9]{6}$` (nie liczy się nigdzie) |
| `POST /v1/authenticator/invalidate-codes` | `mcp-gateway` | wewnętrzny JWT z `tool` | `204`, idempotentne |
| `POST /v1/admin/users/{sub}/authenticator/reset` | `mcp-offboarding` | brak (autoryzacja certyfikatem) | `204`, idempotentne; `sub` ze ścieżki to jedyny taki przypadek w C4 (obok `purge`) |
| `POST /v1/admin/users/{sub}/purge` | `mcp-offboarding` | brak (autoryzacja certyfikatem) | `204`, idempotentne; usuwa wszystko, co broker trzyma o użytkowniku (sekcja Offboarding) |
| `GET /actuator/health` | dowolny z wewnętrznego CA | brak | `UP`/`DOWN` |

Każda inna ścieżka i metoda odpowiada `404 not_found_or_denied`. C4 nie ma 500:
nieoczekiwany błąd i niedostępna zależność (OpenBao, PostgreSQL, Redis, JWKS gateway'a lub IdP) dają
`503 upstream_unavailable`.

Kolejność kontroli w `CallerAuthenticationFilter`: operacja znana (inaczej 404), CN dozwolony dla operacji
zgodnie z `x-allowed-client-cn` (inaczej 403), token pasujący do CN (inaczej 401). `sub` zawsze pochodzi z
tokenu; ścieżka, query i ciało nie mogą go wskazać (nieznane pola w JSON -> 400). Ciało jest ograniczone do
16 KB liczonych przy czytaniu, więc limit działa także dla `Transfer-Encoding: chunked` bez `Content-Length`.

Wewnętrzny JWT C2 sprawdzany jest dokładnie według wektorów `test-vectors/jwt` z 5.1.0 (wszystkie
przechodzą, także co do powodu odrzucenia): tylko ES256, `kid` z JWKS gateway'a, podpis, kształt claimów
wariantu, `iss`, `aud` jako napis, `exp` z tolerancją 30 s, `iat` nie z przyszłości, czas życia do 60 s,
`rid == X-Request-Id`, wariant serwisowy tylko dla `GET /v1/systems`, `tool` wymagany przy `resolve` i
zabroniony przy `GET /v1/systems` (CC-038), `vs` i `vsc` nie istnieją (token z którymkolwiek to `401 invalid_claims`, CC-173)
(CC-056), `jti` jednorazowy (Redis, `SET NX EX` pod `jti:mcp-credential-broker:`). Opublikowane klucze testowe
(`kid` z prefiksem `test-` i, niezależnie od `kid`, klucze o skrócie SPKI z `test-vectors/keys`) są odrzucane
z powodem `test_key_not_allowed`, chyba że `MCP_ALLOW_TEST_KEYS=true` (CC-044). Klucze z `kid` zaczynającym się od `dev-`
(stos dev generuje własne) wymagają trybu dev (CC-137): `MCP_ALLOW_TEST_KEYS=true` **i** aktywnego profilu Springa `devstack`
(`SPRING_PROFILES_ACTIVE=devstack`); samo `MCP_ALLOW_TEST_KEYS` ich nie dopuszcza.

`PUT secret` woła whoami systemu z nowym sekretem (Jira DC: `GET /rest/api/2/myself`, login w `name`; Confluence DC: `GET /rest/api/user/current`,
login w `username`, CC-073; GitLab: `GET /api/v4/user`, login w `username`; bez podążania za przekierowaniami, TLS z zaufaniem do wewnętrznego CA) tylko po to, żeby sprawdzić ważność sekretu i odczytać konto (`backendUser`). Odrzucony
sekret nie jest nigdzie zapisywany. Zastąpienie istniejącego połączenia publikuje
`credential.invalidated` (CC-046). `subjectToken` w `resolve` dla systemu, który nie jest `token-exchange`,
daje 400.

`expiresAt` w `PUT secret` jest opcjonalną informacją użytkownika (CC-084 po zmianie w 2.2.1): broker przyjmuje
każdą poprawną datę UTC albo brak pola i niczego nie sprawdza (data z przeszłości daje od razu `expired`). Status
`expiring` (mniej niż 7 dni) istnieje tylko przy podanej dacie.

Konto w systemie docelowym nie jest porównywane z tożsamością SSO (decyzja człowieka 2026-10-28, CC-101): ta sama osoba
ma różne loginy w różnych systemach (np. `asmith`, `alice.smith`, `smith8`), więc reguła odrzucałaby
uczciwych użytkowników. Whoami służy do dwóch rzeczy: ważność poświadczenia (`422 secret_invalid`) i `backendUser`
(zapisany w metadanych, zwracany w `GET /v1/connections`, `PUT secret` i `oauth/complete`; portal pokazuje "Połączono
jako ..."). Użytkownik może więc podpiąć PAT dowolnego konta, do którego ma poświadczenie. `identity_mismatch` nie jest
zwracane.

To, które konto podpięto, zostaje w audycie: zdarzenie `connection_change` ma `backendUser` (C8, 2.2.5, CC-117), także przy odświeżaniu
i rozłączeniu. Login, którego schemat C8 by nie przyjął (ponad 255 znaków, znaki sterujące, niesparowany surogat), jest
pomijany w zdarzeniu z ostrzeżeniem bez wartości w logu aplikacji, a połączenie mimo to powstaje: to świadoma decyzja.

## token-exchange i service-account (M4)

Systemy tych typów opisują cały system: `supported-types` to dokładnie jeden typ, bez mieszania z typami użytkownika (start się nie uda).
Użytkownik nie ma połączenia z takim systemem, więc `GET /v1/connections` go nie zwraca, a `PUT secret`, `oauth/*` dają `400`.

**`token-exchange` (OpenSearch, adapter `opensearch`, CC-157).** `resolve` wymaga `subjectToken`: tokenu użytkownika z `aud=mcp-credential-broker`
(gateway wymienia na niego token C1). Broker sprawdza go jak token BFF (podpis i `iss` względem JWKS IdP, `aud`, `exp` z tolerancją 30 s) i
wymaga, żeby `sub` był równy `sub` wewnętrznego JWT; inaczej `400 invalid_request` (bez podania, która kontrola zawiodła) i audyt
`credential_resolve` / `subject_token_invalid` (denied). Potem wymienia go w IdP (RFC 8693, `client_secret_basic`, `audience` i `scope`
z konfiguracji systemu) i zwraca `scheme: Bearer`, `type: token-exchange`, `expiresAt` zawsze (z `expires_in`, a gdy IdP go pomija z `exp`
wydanego tokenu; bez żadnego z nich `503`) i `cacheTtlSeconds` nie większe niż 60 i nie dłuższe niż do `expiresAt`. Nic nie jest zapisywane, broker też
nie cache'uje wymiany. Odpowiedzi IdP: `access_denied`, `invalid_grant`, `invalid_target`, `invalid_request` i `invalid_token`
to odmowa dla użytkownika (`403 exchange_denied`, audyt `exchange_denied`, errorCode `access_denied`); `invalid_scope`, `invalid_client`, `unauthorized_client`,
5xx, brak odpowiedzi i każdy nieznany błąd to `503` (to defekt instalacji albo IdP, nie decyzja o użytkowniku). Klucz wymiany: klient poufny z
`broker.systems.opensearch.token-exchange.client-id`, sekret w OpenBao `secret/data/mcp/oauth-clients/opensearch` (pole `client_secret`, ten sam
mechanizm co klient OAuth GitLaba; `client-secret` w konfiguracji tylko dla dev).

```yaml
broker.systems.opensearch:
  base-url: https://opensearch.internal:9200   # wymagany przez schemat konfiguracji, broker go nie wywołuje
  adapter: opensearch
  supported-types: [token-exchange]
  default-type: token-exchange
  token-exchange:
    client-id: mcp-credential-broker
    token-url: https://keycloak.internal/realms/corp/protocol/openid-connect/token
    audience: opensearch
    scopes: [opensearch-audience]
```

**`service-account` (Service Desk, adapter `generic-rest`, CC-157).** Klucz konta leży w OpenBao w `secret/data/mcp/service-accounts/<system>`
(zapisuje operator, broker ma tylko odczyt): `value` (to, co idzie po schemacie w nagłówku; przy Basic musi to być już `base64(login:hasło)`) albo, dla `secret-scheme: Basic`, `username` (bez `:`) i `password`
(broker składa `base64(login:hasło)`), oraz opcjonalne `expires_at` (RFC 3339) przy rotacji na harmonogram. `scheme` to `secret-scheme` systemu (`Bearer`,
`Basic`, `Token`, `ApiKey`), `expiresAt` to `expires_at` albo `null`, `cacheTtlSeconds` nie dłuższe niż do `expiresAt`. Klucza nie cache'uje nikt po
stronie brokera, więc rotacja w OpenBao działa od następnego `resolve`. Brak wpisu, brak wartości, wartość z białymi znakami, zły `expires_at` albo
klucz po terminie to `503` (fail-closed; nikt po stronie użytkownika tego nie naprawi) z audytem `secret_store_unavailable`.

**`422 system_not_configured` (CC-158).** System z kontraktów (`jira`, `confluence`, `gitlab`, `servicedesk`, `opensearch`), którego broker nie ma w
konfiguracji, w `resolve`, `oauth/start` i `oauth/complete` daje `422 {"error":"system_not_configured"}` (zamiast `400`). Audyt:
`credential_resolve` z powodem `system_not_configured` i wynikiem `error` (w `oauth/*` to samo w `connection_change`). Identyfikator spoza
kontraktów to nadal `400`.

## Offboarding i czyszczenie (M4)

**`POST /v1/admin/users/{sub}/purge` (CN `mcp-offboarding`, bez tokenu, CC-155).** Usuwa w tej kolejności ważności: wszystkie połączenia
z sekretami (odwołanie tokenów u dostawcy dla `user-oauth`, potem sekret ze wszystkimi wersjami KV, potem wiersz, `credential.invalidated` dla
każdego), wszystkie wartości pod `secret/mcp/connections/<sha256(sub)>/` także te, na które nie wskazuje żaden wiersz (po nieudanym kasowaniu), przepływy
OAuth w toku, rejestrację Authenticatora z oboma ziarnami i wiersz blokady (to jedyne wywołanie, które ją zdejmuje: użytkownika już nie ma).
Kroki są niezależne: awaria jednego (np. OpenBao) nie zatrzymuje pozostałych, a po ich wykonaniu wywołanie kończy się `503`; powtórzenie
dokańcza resztę (połączenie, którego sekretu nie dało się skasować, zostaje w bazie właśnie po to). Odpowiedź `204` jest ta sama dla użytkownika, którego
broker nie zna i dla `sub` dłuższego niż 255 znaków. Zalecane jest powtórzenie po wylogowaniu back-channel w portalu: przepływ OAuth otwarty w trakcie mógł założyć połączenie po pierwszym wywołaniu.
Po `purge` ten sam `sub` nie może założyć ani zamienić połączenia przez `broker.retention.purge-marker-ttl` (domyślnie 30 min; start odmawia, gdy jest krótszy niż `broker.oauth-flow.flow-ttl`): `PUT secret`, `oauth/start` i `oauth/complete` dają `503` z powodem audytu `user_offboarding`. Okno do 60 min na wygaśnięcie tokenu C1 jest przyjęte przez człowieka.

Audyt `purge`: `connection_change` z powodem `user_purged` dla każdego połączenia (z `credentialType` i `backendUser`), `authenticator` z
`authenticator_removed`, gdy była rejestracja albo trwała rejestracja, oraz **zawsze** jedno `admin_change` z powodem `user_purged` (`ok`, także gdy nic nie
było do usunięcia; `error`, gdy któryś krok się nie udał). Nieudane odwołanie tokenów u dostawcy (przy `purge` i przy zwykłym `DELETE`) zostawia dodatkowe
`connection_change` z powodem `provider_revoke_failed` i wynikiem `error`; połączenie jest usuwane mimo to. Gdy to magazyn sekretów nie odpowiada (tokenów nie da się odczytać do odwołania), usunięcie kończy się `503` i jest powtarzane.

**Czyszczenie nieużywanych połączeń (CC-155).** Zadanie w tle (`broker.retention.cleanup-interval`, domyślnie 1 h) usuwa połączenia, których ostatnie użycie
(a gdy nigdy nie użyto, utworzenie) jest starsze niż `broker.retention.unused-after` (domyślnie 180 dni), tą samą drogą co `DELETE`; audyt
`connection_change` z powodem `unused_cleanup`. Wiersz jest czytany ponownie pod blokadą połączenia, więc użyte w międzyczasie zostaje. Broker nie dodaje statusu
"wygasające" dla portalu: `GET /v1/connections` podaje `lastUsedAt` i `connectedAt`, z których portal wylicza ostrzeżenie (kontrakt mówi, że oznacza je portal; wartość
retencji jest konfiguracją brokera, zob. Propozycje CC w STATUS.md).

## Limity (M4)

Limity na `sub`, licznik stałego okna w Redisie (`broker:rate:<operacja>:<sha256(sub)>`, `INCR` i `EXPIRE`), ponad limit `429 {"error":"rate_limited"}` z
`Retry-After` (sekundy do końca okna, co najmniej 1), bez nagłówków `X-RateLimit-*`; audyt `connection_change` z powodem `rate_limited` (denied, errorCode
`rate_limited`). `broker.rate-limits.oauth-starts` (domyślnie 10) i `oauth-completions` (20) na `window` (1 min): wartości własne brokera, kontrakt ich nie
ustala. Start rejestracji Authenticatora: `broker.authenticator.enrollment-starts-per-hour`, domyślnie 10 na godzinę (CC-151), też z `Retry-After`. Redis
niedostępny to `503` (bez licznika limitu nie da się egzekwować, a operacje i tak potrzebują Redisa).

## Połącz przez OAuth (user-oauth, GitLab)

`oauth/start` i `oauth/complete` (C4) obsługują authorization code z PKCE (S256) jako klient poufny. Broker nie
ma żadnego adresu wywoływanego przez przeglądarkę: `redirect_uri` to callback BFF
`<MCP_PORTAL_URL>/api/v1/oauth/callback`, a BFF przekazuje `code` i `state` do `complete`.

1. `start`: broker losuje `flowId`, `state` (32 bajty) i `code_verifier` (32 bajty), zapisuje je razem z `sub` z
   tokenu BFF w Redisie (`broker:oauth:flow:<flowId>`, 10 min, GETDEL = jednorazowe) i zwraca `authorizeUrl`
   (`client_id`, `redirect_uri`, `state`, `code_challenge` S256, `scope` z `oauth-scopes`). Kolejny `start` tego
   samego użytkownika dla tego samego systemu unieważnia poprzedni niedokończony przepływ (wygrywa ostatni link).
   `returnPath` jest walidowany (CC-032) i nie jest przechowywany: BFF sam wie, dokąd wrócić.
2. `complete`: `sub` z tokenu musi być `sub` przepływu (inaczej `422 flow_invalid`, a przepływ właściciela
   zostaje nietknięty, żeby obcy nie mógł go zużyć); potem przepływ jest zużywany atomowo, `state` porównywany w
   stałym czasie, kod wymieniany z `code_verifier`, a token sprawdzany whoami (`/api/v4/user`, `username`), z którego
   pochodzi `backendUser` (bez porównania z SSO). Każda droga po wymianie kodu, która nic nie zapisuje, odwołuje
   wydane tokeny u dostawcy (`/oauth/revoke`, best effort). Kod odrzucony przez dostawcę (`invalid_grant`: użyty, wygasły, zły
   verifier) -> `422 flow_invalid`. Dostawca niedostępny, timeout, `invalid_client` -> `503 upstream_unavailable`
   (po stronie BFF to `provider_error`; `cancelled` BFF ustala sam z `error=access_denied`, do brokera wtedy nie
   dzwoni, a przepływ wygasa po 10 min).
3. Zapis: access i refresh token razem w OpenBao (Transit + KV v2, jak PAT), metadane w PostgreSQL
   (`access_expires_at`); `credential.invalidated` przy zastąpieniu istniejącego połączenia (CC-046).

`Connection.expiresAt` dla `user-oauth` jest `null`: access token (GitLab: 2 h) odnawia broker, więc nie jest
terminem dla użytkownika. Status to `connected`, dopóki dostawca honoruje refresh token, potem `revoked`.

Odświeżanie: `resolve` odnawia token, gdy zostało mu mniej niż `broker.oauth-flow.refresh-margin` (2 min, musi
być większe od `cache-ttl-seconds`, żeby wydany token przeżył cache gateway'a), a zadanie w tle co minutę odnawia
te, którym zostało mniej niż `sweep-window` (5 min). Odnowienie pod blokadą w Redisie (`SET NX PX` z losowym właścicielem i dzierżawą 60 s, jedno naraz
na (użytkownik, system); tę samą blokadę biorą `DELETE`, `complete` i `PUT secret`, a zapis odnowienia jest warunkowy
na wersji sekretu), bo dostawcy rotują refresh tokeny i równoległe odnowienia wyglądałyby jak odwołanie
grantu. Rotowany refresh token jest zapisywany nową wersją sekretu. `invalid_grant` przy odnowieniu ->
połączenie `revoked`, sekret usunięty, `credential.invalidated`, `resolve` -> `409 credential_required`. Awaria
dostawcy przy jeszcze ważnym tokenie nie przerywa `resolve`; przy wygasłym -> `503`. Odnowienie nie publikuje
`credential.invalidated` (ten sam grant).

`DELETE /v1/connections/{system}` odwołuje u dostawcy refresh i access token przed usunięciem lokalnym
(best effort: awaria dostawcy nie blokuje rozłączenia).

Konfiguracja GitLaba (opcjonalna, jak Confluence; zmienne Spring relaxed binding, `application.yml` go nie zawiera):

| Zmienna | Znaczenie |
| --- | --- |
| `BROKER_SYSTEMS_GITLAB_BASEURL` | adres GitLaba, z którego korzysta broker (whoami, token, revoke) |
| `BROKER_SYSTEMS_GITLAB_ADAPTER` | `gitlab` |
| `BROKER_SYSTEMS_GITLAB_SUPPORTEDTYPES`, `..._DEFAULTTYPE` | np. `user-oauth,user-secret` i `user-oauth` |
| `BROKER_SYSTEMS_GITLAB_OAUTHSCOPES` | zakresy w `scope` i w `GET /v1/systems`, np. `read_api` |
| `BROKER_SYSTEMS_GITLAB_OAUTH_CLIENTID`, `..._CLIENTSECRET` | klient OAuth zarejestrowany w GitLabie (redirect URI = callback BFF) |
| `BROKER_SYSTEMS_GITLAB_OAUTH_AUTHORIZEURL` | adres autoryzacji otwierany w przeglądarce; domyślnie `<BASEURL>/oauth/authorize` (osobny, gdy GitLab ma inny adres dla przeglądarki niż dla brokera) |
| `BROKER_SYSTEMS_GITLAB_OAUTH_TOKENURL`, `..._REVOKEURL` | opcjonalnie; domyślnie `<BASEURL>/oauth/token` i `/oauth/revoke` |

`client_secret` broker czyta z OpenBao (`secret/mcp/oauth-clients/<system>`, pole `client_secret`, cache 5 min;
`broker.openbao.oauth-clients-prefix`). `..._CLIENTSECRET` to zapas wyłącznie dla developmentu: bez
`MCP_ALLOW_PLAIN_HTTP=true` jego ustawienie przerywa start.
`scripts/run-dev-host.sh` ustawia powyższe, gdy podano `MCP_GITLAB_URL` (opcjonalnie `MCP_GITLAB_CLIENT_ID`,
`MCP_GITLAB_AUTHORIZE_URL`, `MCP_GITLAB_SCOPES`, `MCP_GITLAB_CLIENT_SECRET`).

## Authenticator TOTP (M3)

Potwierdzenie akcji `DESTRUCTIVE` to kod z aplikacji Authenticator (CC-091), który weryfikuje broker. BFF zakłada i
usuwa rejestrację po świeżym MFA w IdP; broker ufa BFF co do tej świeżości (CN `mcp-portal-bff`, CC-092). Weryfikację,
spalanie kodów i odczyt stanu dla gateway'a wolno wołać tylko z CN `mcp-gateway` i wewnętrznym JWT z `tool`.

- **Algorytm:** RFC 6238, HMAC-SHA-1, 6 cyfr, krok 30 s, okno t-1..t+1 zegara brokera (stałe), porównanie kodu w stałym czasie
  po wszystkich krokach okna. Krok przyjmowany raz: `lastAcceptedStep` rośnie jednym warunkowym zapisem pod blokadą
  wiersza, kod kroku nie nowszego to `replayed`.
- **Limity** (stałe z kontraktu, stałe w kodzie `AuthenticatorLimits`, nie konfiguracja): 5 błędnych (`invalid` lub `replayed`) w 15 min -> blokada 15 min;
  20 błędnych w 24 h (okno kroczące, sukces licznika nie zeruje) -> `state: disabled` do ponownej rejestracji.
  `locked`, `disabled`, `burned` i zły format nie są błędnymi kodami. Blokada należy do użytkownika: usunięcie, reset i
  nowa rejestracja jej nie zdejmują, tylko upływ czasu. Aktywacja nowej rejestracji zeruje oba liczniki i stan `disabled`.
- **Atomowość:** każda zmiana liczników, blokady i rejestracji jednego `sub` to jedna transakcja z `select ... for update`
  na wierszu `authenticator` (z `lock_timeout` 2 s). Żadne wywołanie OpenBao nie odbywa się pod tą blokadą: ziarno jest
  czytane (a przy potwierdzeniu rejestracji zapisywane) przed transakcją, w transakcji tylko porównanie
  `registration_id` i zapis metadanych, a usuwanie ziaren następuje po commicie. Z tej kolejności wynika niezmiennik:
  wiersz `active` zawsze ma ziarno w magazynie. Gdy go nie ma (utrata po stronie OpenBao), `verify` odpowiada `503` raz
  (audyt `authenticator_seed_missing`) i zmienia rejestrację na `none`; potem `not_registered`, a użytkownik rejestruje się
  od nowa. 50 równoległych błędnych kodów po HTTP daje dokładnie 5 sprawdzeń (`invalid`) i resztę `locked`; ten sam
  poprawny kod w 20 równoległych żądaniach przyjmuje jedno żądanie.
- **Spójność z OpenBao:** wpis, o którym baza nie wie (zapis przed nieudanym commitem, nieudane kasowanie po commicie),
  usuwa zadanie w tle (`orphan-sweep-interval`, domyślnie 30 min) po 15 min karencji: ziarno aktywne bez rejestracji
  `active`/`disabled` i ziarno `pending` bez rejestracji w toku. Usunięcie i reset kasują ziarna bezwarunkowo, także gdy
  wiersza już nie ma, więc powtórzenie po `503` kończy robotę. Przy nowej rejestracji ze stanu `disabled` stare ziarno
  jest kasowane (wszystkie wersje KV) przed zapisem nowego.
- **`invalidate-codes` (CC-128):** `burnedThrough = max(burnedThrough, krok zegara + 1)`, `lastAcceptedStep = max(..., burnedThrough)`.
  Kod spalonego kroku daje `burned`, nie jest błędem i nie rusza limitów. Użytkownik bez aktywnej rejestracji: `204`.
- **Rejestracja:** ziarno 20 bajtów z `SecureRandom`, w odpowiedzi `201` jako Base32 (`secret`) i w `otpauthUri` w stałej
  formie z kontraktu. Rejestracja w toku żyje 10 min, trzy błędne kody ją niszczą (`enrollment_invalid`), ponowny start ją
  zastępuje, najwyżej 10 startów na godzinę (`429` z `Retry-After` do końca okna). Zadanie w tle (co minutę) kasuje ziarna rejestracji, której nikt nie
  potwierdził. Błędne kody rejestracji nie liczą się do blokady weryfikacji. Ze stanu `disabled` start jest dozwolony.
- **Przechowywanie ziarna:** wyłącznie OpenBao Transit bez envelope (klucz `mcp-authenticators`, nie opuszcza OpenBao),
  szyfrogram w KV v2 pod `secret/data/mcp/authenticators/<sha256(sub)>` (aktywne) i `.../<sha256(sub)>/pending` (w toku).
  Odszyfrowany rekord ma `sub` i rodzaj; niezgodność (szyfrogram przeniesiony pod cudzą ścieżkę albo z `pending` na
  aktywne) daje 503. PostgreSQL trzyma metadane (tabele `authenticator`, `authenticator_failure`): stan, czasy, krok,
  liczniki, blokadę. Ziarna nie ma w Redisie, bazie, logach, audycie ani w odpowiedziach poza `201` rejestracji (sprawdza
  to `@AfterAll` testu integracyjnego na wszystkich zarejestrowanych odpowiedziach). Niedostępny OpenBao -> 503, nigdy
  `ok`.
- **Audyt:** `event: authenticator` z powodami z kontraktu: `authenticator_enrollment_started`, `authenticator_registered`,
  `authenticator_enrollment_failed`, `authenticator_removed`, `authenticator_reset_by_admin`, `totp_verified`, `totp_invalid`,
  `totp_replayed`, `totp_burned`, `totp_locked` (z `errorCode: rate_limited`), `totp_disabled`, `totp_not_registered`,
  `totp_steps_burned` i `authenticator_disabled` (osobna linia przy błędzie, który wyłączył Authenticator). Wywołania
  gateway'a niosą `client`, `tool`, `policyRevision` z JWT. Kodu, ziarna ani `otpauthUri` nie ma w zdarzeniu.
- **OpenBao:** wymaga klucza Transit `mcp-authenticators` i polityki na `secret/data/mcp/authenticators/*`,
  `secret/metadata/mcp/authenticators/*` oraz `transit/encrypt|decrypt/mcp-authenticators` dla AppRole brokera
  (szczegóły w [STATUS.md](STATUS.md), sekcja "Czego broker potrzebuje od innych").

## Wiele instancji (M5)

Broker działa w kilku replikach na jednej bazie PostgreSQL, jednym Redisie i jednym OpenBao. Stan krytyczny dla TOTP jest
wyłącznie w bazie: licznik błędnych kodów, blokada, `last_accepted_step`, `burned_through` zmienia się w transakcji z
`select ... for update` na wierszu użytkownika, więc dwie instancje szeregują się tak jak dwa wątki jednej. Potwierdzenia rejestracji
jednego użytkownika są wyłączne (`pg_try_advisory_xact_lock` na `sub`): drugie równoległe potwierdzenie dostaje `422 enrollment_invalid`
bez dotykania magazynu ziaren (wcześniej przegrywający kasował ziarno zwycięzcy). W pamięci instancji nie ma nic, na czym opiera się werdykt
(są tylko pamięci podręczne kluczy JWKS, tokenu OpenBao i sekretów klientów OAuth).

Blokada zmian połączenia (`RefreshLock`): `SET NX PX` z losowym właścicielem, zwolnienie skryptem Lua (porównanie i `DEL` w jednym
kroku; ACL brokera ma `eval` i `evalsha`), dzierżawa 60 s, oczekiwanie 3 s. Blokadę biorą odświeżanie, `PUT secret`, `oauth/complete` i `purge` dla każdego systemu, nie tylko OAuth (inaczej `PUT` obok `purge`
zapisałby użytkownika po offboardingu), więc te operacje wymagają Redisa (`503` bez niego). `DELETE` bierze ją tylko dla systemów z OAuth
(odświeżanie w toku nie może go nadpisać); dla pozostałych działa bez Redisa, bo usunięcie nikogo nie przywraca. Zabita instancja zwalnia blokadę przez koniec dzierżawy; zapis po odświeżeniu jest warunkowy względem wersji
sekretu (fencing). Zapis zrotowanych poświadczeń (`SecretStore.putRotated`) omija bezpiecznik klienta OpenBao i jest ponawiany do 15 s
łącznie (jeden termin na zapis sekretu i przełączenie wiersza). Gdy odpowiedź bazy na przełączenie zginie, o wyniku decyduje odczyt wiersza:
wersja równa nowej to sukces, inna to usunięcie nowej wersji, a brak odczytu to `503` bez usuwania czegokolwiek i bez odwoływania tokenów.
Przed pytaniem dostawcy broker czyta sekret z magazynu, żeby nie zużyć tokenu, którego nie da się zapisać. Wersje sekretów, na które nie wskazuje żaden wiersz, zadanie co 6 h tylko raportuje (`broker.retention.orphan-sweep-delete=false` domyślnie).
Po włączeniu usuwa najwyżej `orphan-max-deletes-per-run` (50) wartości starszych niż `orphan-secrets-after` (1 h), nie rusza wartości systemów z OAuth
(bez `sub` nie da się odwołać grantu u dostawcy) i odmawia, gdy zbiór referencji jest pusty przy niepustym magazynie albo gdy sierot jest więcej niż
`orphan-max-fraction` (0,2). Ograniczenie: gdy dostawca rotuje
refresh token, a instancja zginie po jego wydaniu przed zapisem, stary token jest zużyty i połączenie wymaga ponownego połączenia przez
użytkownika (`invalid_grant` -> `revoked`). `purge` kasuje wartości bez wiersza (`deleteAllOf`) dopiero, gdy usunięto wszystkie połączenia;
inaczej kończy się błędem i powtórzenie odwoła grant u dostawcy. Purge ustawia na starcie znacznik w Redisie (`broker.retention.purge-marker-ttl`, domyślnie 30 min, ma przeżyć czas życia przepływu OAuth i tokenu portalu;
`broker:oauth:purging:<hash>`), który sprawdzają `PUT secret`, `oauth/start` i `oauth/complete` (503, dopóki nie wygaśnie; ponowne podłączenie tego samego `sub`
w tym oknie jest odmawiane). Potem purge bierze i zwalnia blokadę każdego systemu (czeka na zapisy, które ją trzymały), czyta wiersze jeszcze raz i dopiero wtedy
wywołuje `deleteAllOf`. Bez Redisa purge nie próbuje przepływów ani blokad (każda próba kosztuje timeout), usuwa tylko rejestrację Authenticatora i kończy się `503`. Wpis, który magazyn zwraca, ale nie da się go odczytać (Transit odmawia uszkodzonego
szyfrogramu: `cipher: message authentication failed` albo `invalid ciphertext...`; wpis cudzej ścieżki), nie blokuje purge (inne odmowy 400/422, np. brak klucza, to `503` i powtórzenie); także przy zamianie połączenia (`PUT`, `oauth/complete`): połączenie jest usuwane z audytem `provider_revoke_failed`; niedostępny magazyn daje `503` i powtórzenie.

Zależność niedostępna (Redis, OpenBao, PostgreSQL; sprawdzane przy wstrzymanym kontenerze): operacja, która jej potrzebuje, daje
`503 upstream_unavailable` w ciągu kilku sekund, nigdy sukces z pominiętą kontrolą ani `500`. Klient OpenBao po 3 wywołaniach z rzędu bez odpowiedzi
odpowiada błędem od razu przez 2 s, żeby awaria nie trzymała wątków żądań po 5 s na każdy krok. Odpowiedź `404` znaczy "brak sekretu" tylko z pustym `errors` albo `data` jako obiektem;
każda inna (też `errors` z treścią, np. "no handler for route") to `503`; ziarno TOTP nie jest wtedy uznawane za utracone. `oauth/start` nie potrzebuje OpenBao ani PostgreSQL
(stan w Redisie). Polecenie wysłane do wstrzymanego Redisa wykonuje się po jego wznowieniu, więc blokada może zostać wzięta "dla nikogo" do końca dzierżawy
(przy błędzie broker próbuje ją zwolnić tym samym właścicielem).

### Znane ograniczenia (M5)

- Licznik limitów OAuth (`INCR` i `EXPIRE` w Redisie) nie jest atomowy: licznik bez TTL po przerwaniu procesu dostaje TTL przy pierwszym przekroczeniu limitu.
- Sprzątanie osieroconych ziaren Authenticatora i sekretów listuje magazyn, a potem usuwa; zapis między listowaniem a usunięciem chroni tylko karencja
  (`ORPHAN_GRACE`, `orphan-secrets-after`). Sprzątanie sekretów domyślnie tylko raportuje.
- Ponowne podłączenie tego samego `sub` w oknie znacznika purge jest odmawiane także wtedy, gdy purge był pomyłką; znacznik można zdjąć w Redisie
  (`broker:oauth:purging:<sha256(sub)>`) albo poczekać.
- Zrotowany refresh token zapisany tylko w pamięci instancji, która zginęła przed zapisem, jest nie do odzyskania (połączenie `revoked`).
- Przy Redisie w dół `DELETE` połączenia OAuth, `PUT`, `oauth/*` i `purge` dają `503`; `resolve` i `verify` też (jti).
- Wynik nieznany po odświeżeniu (wiersz nie dał się odczytać, `RefreshOutcomeUnknownException`): jeśli wiersz się nie przełączył, nowa wartość z żywymi tokenami zostaje
  sierotą, a `deleteAllOf` w purge kasuje ją bez odwołania u dostawcy i bez audytu; grant zostaje u dostawcy.
- Sweep osieroconych sekretów przy włączonym kasowaniu: poniżej 10 wartości w magazynie próg ułamka nie działa, `orphan-secrets-after` nie ma dolnej granicy,
  a sieroty systemów z OAuth nie znikają i liczą się do ułamka (przy ich nadmiarze sweep odmawia).
- `RefreshLock`: fencing (zapis warunkowy względem wersji) mają odświeżanie i `markUnusable`, ale nie `replace` (`PUT`, `oauth/complete`); `PUT` wznowiony po pauzie JVM
  dłuższej niż dzierżawa (60 s) może przejść barierę purge.

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
Jedno pobranie JWKS ma twardy limit całej wymiany (domyślnie 5 s, `broker.gateway-jwt.jwks-fetch-timeout`) i ciała (256 KiB).
Wyszukiwanie z nieznanym `kid` albo na kluczach starszych niż limit czeka na trwające pobranie najwyżej
timeout + 1 s, a jednocześnie czeka co najwyżej 8 wyszukiwań; kolejne dostają 503 od razu, więc zawieszony
endpoint JWKS nie zajmie puli wątków. Nieznany `kid` przy nieudanym odświeżeniu to 503, nie 401.
Brak sekretu przy istniejącym wierszu połączenia (utrata danych w OpenBao): `resolve` daje
`credential_required`, a operator dostaje ostrzeżenie w logu WARN "Connection metadata without a stored
secret" (pierwsze od razu, powtórki co najwyżej raz na 15 min z liczbą zdarzeń; bez `sub` i ścieżki sekretu).
Licznik `broker.connection.secret_missing{system,place}` jest tylko w rejestrze procesu: `/actuator` wystawia
wyłącznie `health`, więc na dziś sygnałem dla operatora jest log (ekspozycja metryk to osobna decyzja).
Pusta odpowiedź JWKS (bez użytecznego klucza) jest traktowana jak nieudane odświeżenie: poprzednie klucze
zostają, a nieznany `kid` daje 503.
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
| `MCP_ALLOW_TEST_KEYS` | domyślnie `false`: opublikowane klucze testowe (`test-`) odrzucane; `true` tylko w testach i lokalnie; klucze `dev-` dodatkowo wymagają profilu `devstack` (CC-137) |
| `BROKER_SYSTEMS_OPENSEARCH_*`, `BROKER_SYSTEMS_SERVICEDESK_*` | opcjonalne systemy typu `token-exchange` i `service-account` (sekcja wyżej): `BASEURL`, `ADAPTER`, `SUPPORTEDTYPES`, `DEFAULTTYPE`, `SECRETSCHEME`, `TOKENEXCHANGE_CLIENTID`, `_TOKENURL`, `_AUDIENCE`, `_SCOPES` |
| `BROKER_RETENTION_UNUSEDAFTER`, `BROKER_RETENTION_CLEANUPINTERVAL`, `BROKER_RETENTION_BATCHSIZE` | czyszczenie nieużywanych połączeń: `180d`, `PT1H`, `100` |
| `BROKER_RATELIMITS_OAUTHSTARTS`, `BROKER_RATELIMITS_OAUTHCOMPLETIONS`, `BROKER_RATELIMITS_WINDOW` | limity OAuth na `sub`: `10`, `20`, `1m` |
| `BROKER_OPENBAO_SERVICEACCOUNTSPREFIX` | ścieżka kluczy kont serwisowych w KV, domyślnie `mcp/service-accounts` |
| `MCP_JIRA_URL` | adres Jiry (whoami), wymagany |
| `BROKER_SYSTEMS_CONFLUENCE_*` | opcjonalny system `confluence` (adapter `atlassian-dc`): `BASEURL`, `ADAPTER=atlassian-dc`, `SUPPORTEDTYPES=user-secret`, `DEFAULTTYPE=user-secret`; ten sam sposób co `jira` w `application.yml` |
| `MCP_PORTAL_URL` | baza `connectUrl` w `409 credential_required`, wymagany |
| `MCP_ALLOW_PLAIN_HTTP` | domyślnie `false`; `true` dopuszcza `http` do OpenBao, JWKS i whoami (tylko dev) |

Authenticator (`broker.authenticator.*`): `transit-key` (`mcp-authenticators`), `path-prefix` (`mcp/authenticators`),
`enrollment-starts-per-hour` (10, wartość własna brokera), `sweep-interval` (1 min), `orphan-sweep-interval` (30 min). Okno,
limity błędów, blokada i reguły rejestracji są stałe (kontrakt).

Systemy i typy poświadczeń są w `broker.systems` (YAML). Znane są `user-secret` (Jira, Confluence, GitLab), `user-oauth` (GitLab),
`token-exchange` (OpenSearch) i `service-account` (Service Desk); niespójna konfiguracja (adapter nie obsługuje typu, `token-exchange` albo `service-account`
zmieszany z innym typem, brak bloku `token-exchange`) zatrzymuje start.

## Budowanie i testy

Wymaga JDK 25 i Dockera (Testcontainers).

```bash
export JAVA_HOME=/opt/homebrew/Cellar/openjdk@25/25.0.4.1/libexec/openjdk.jdk/Contents/Home
./mvnw -B verify                          # testy jednostkowe, kontraktowe i integracyjne + jar
docker build -t mcp-credential-broker:dev .
```

| Test | Co sprawdza |
| --- | --- |
| `InternalJwtVectorTest` | wszystkie wektory C2 z `mcp-contracts` 5.1.0 (także `dev-` z `devstackProfile` i wywołania `authenticator` z `tool`) (wynik i powód, `allowTestKeys` z wektora), klucz testowy pod produkcyjnym `kid` (SPKI), replay |
| `MultiInstanceIntegrationTest` | dwie JVM brokera (porty 18712-18717) na wspólnej bazie: zapis i potwierdzenie rejestracji na różnych instancjach, równoległe potwierdzenia, 5 błędów dokładnie raz, jeden kod raz, spalenie kodów, zabicie instancji (SIGKILL) w trakcie prób, jedno odświeżenie na dwóch instancjach, martwy właściciel blokady, równoczesne migracje pustej bazy |
| `FailClosedIntegrationTest` | nadużycie 15: 12 operacji przy wstrzymanym Redisie, OpenBao i PostgreSQL, kody i czasy, brak `internal_error`, powrót po wznowieniu |
| `ReturnPathTest` | walidator `returnPath` (CC-032) na wektorach `return-paths/`, używany przez `oauth/start` |
| `OAuthIntegrationTest` | przepływ GitLaba na stubie WireMock: PKCE, state jednorazowy i związany z użytkownikiem, cudzy `flowId`/`state` (zły `state` nie spala przepływu), ponowne użycie, konto o innym loginie (połączone, widoczne jako `backendUser`), błąd i timeout dostawcy, wygasły przepływ, zapis w OpenBao, odświeżanie (rotacja, równoległe, odwołany grant, awaria dostawcy, `DELETE` w trakcie odświeżania, utrata blokady, odwołanie zastąpionego grantu), limit rozmiaru i czasu odpowiedzi dostawcy, zadanie w tle, `DELETE` z odwołaniem, PAT GitLaba; brak tokenów w odpowiedziach poza `resolve` i w logach |
| `TotpVectorTest` | wszystkie scenariusze `test-vectors/totp/` (RFC 6238, okno, jednorazowość kroku, blokada 5/15, limit dzienny, rejestracja, spalanie) na prawdziwym serwisie, PostgreSQL i OpenBao Transit z zegarem ustawianym na `at` kroku; przykłady `rfc6238-sha1` i `otpauth-uri`; sprzątanie nieudanych rejestracji, ziaren bez wiersza (po karencji), nieudane kasowanie ziarna przy usunięciu, utrata ziarna aktywnej rejestracji |
| `AuthenticatorIntegrationTest` | rejestracja po HTTP (nagłówki, schematy, ziarno raz), przechowywanie (szyfrogram w KV, `sub` w rekordzie, baza bez ziarna), 50 równoległych błędnych kodów = 5 sprawdzeń, dobowy limit raz i jedno zdarzenie `authenticator_disabled`, ten sam kod równolegle = jeden `ok`, spalanie, usunięcie i reset (blokada zostaje), ziarno pod cudzą ścieżką = 503, macierz CN i tokenów, `sub` zawsze z tokenu |
| `TokenExchangeIntegrationTest` | wymiana na stubie IdP: żądanie RFC 8693 (pola, `Basic`), `expiresAt` i TTL, `exp` z tokenu gdy brak `expires_in`, `subjectToken` cudzy / zły `aud` / wygasły / zły `iss` / zły podpis / nie JWT -> `400` bez pytania IdP, odmowy IdP -> `403`, awarie IdP -> `503`, nic w OpenBao, brak tokenów i sekretu klienta w logach |
| `ServiceAccountIntegrationTest`, `ServiceAccountKeysTest` | klucz z OpenBao (Bearer, Basic z loginu i hasła, `expires_at`, rotacja bez restartu), brak / po terminie / zły wpis -> `503`, `GET /v1/connections` bez konta, `PUT secret` i `oauth/*` -> `400` |
| `OffboardingIntegrationTest` | `purge` (połączenia, wszystkie wersje KV i wartość bez wiersza, przepływ OAuth w toku, Authenticator z blokadą, odwołanie u dostawcy, `credential.invalidated`, audyt per element i zbiorczy), idempotencja i nieznany `sub`, tylko CN `mcp-offboarding`, `provider_revoke_failed`, awaria OpenBao w trakcie (`503`, powtórzenie kończy), czyszczenie nieużywanych (`unused_cleanup`) |
| `RateLimitIntegrationTest` | `429` z `Retry-After` dla `start` i `complete` na `sub`, inny użytkownik bez wpływu, licznik bez TTL dostaje TTL |
| `OperationsContractTest` | tabela operacji filtra == metody, ścieżki i `x-allowed-client-cn` z OpenAPI C4 |
| `BrokerIntegrationTest` | mTLS, PostgreSQL, Redis z ACL jak w dev, OpenBao (AppRole, KV v2, Transit), fałszywa Jira; odpowiedzi walidowane schematami OpenAPI, audyt schematem C8, zdarzenie schematem C4.3; brak sekretu w odpowiedziach poza `resolve` i w logach |
| `BrokerIntegrationTest` (awarie) | Redis i PostgreSQL wstrzymane (`docker pause`) -> 503 z audytem; szyfrogram przeniesiony pod cudzą ścieżkę -> 503; ciało chunked 200 KB -> 400 bez whoami; sondy ścieżek -> 404 |
| `OpenBaoClientTest` | `renew-self`, ponowne logowanie przy `token_max_ttl`, praca na ważnym tokenie po nieudanym logowaniu |
| `KeySourceTest` | JWKS gateway'a przeterminowany -> 503, niedostępny JWKS IdP -> 503 zamiast 401 |
| `CredentialServiceTest`, `ConnectionTest`, `AuditLogTest`, `TransportSecurityTest` | fail-closed, wersje sekretów, `email_verified`, porównanie ASCII, `subjectToken`, TTL, `lastUsedAt`, escapowanie audytu, `backendUser` w audycie (poprawny, odrzucany, surogaty, błąd zapisu po whoami), wymóg https |
| `AuditEventVectorTest` | wszystkie wektory `audit-events/` z `mcp-contracts` 5.1.0 względem schematu C8 i zgodność `AuditLog.validBackendUser` z wektorami `backendUser` |

## Uruchomienie lokalne w `mcp-platform-dev` (ws-01)

### Obraz w compose (profil `full`)

```bash
./mvnw -B package -DskipTests && docker build -t mcp-credential-broker:dev .
cd ../mcp-platform-dev
make up                                   # infrastruktura
./scripts/compose.sh --profile full up -d --no-deps mcp-credential-broker
make pat USER=alice BROKER_URL=https://localhost:18100                  # 200, backendUser alice
make pat USER=alice SECRET=bob-pat BROKER_URL=https://localhost:18100   # 200, backendUser bob (bez porównania z SSO)
./scripts/compose.sh --profile full rm -sf mcp-credential-broker
```

`make up-full` uruchamia też gateway i `mcp-jira`; bez ich obrazów (`mcp-gateway:dev`,
`mcp-server-jira:dev`) się nie powiedzie, stąd start samego brokera. W compose broker czyta JWKS gateway'a z
`https://mcp-gateway.internal:8443/.well-known/jwks.json` dopiero przy pierwszym `resolve`, więc startuje
bez gateway'a. Póki działa obok stuba C4, oba mają alias `mcp-credential-broker.internal`; po teście
kontener trzeba usunąć (ostatnia komenda).

### Na hoście

Wymaga działającego stosu `mcp-platform-dev` (Keycloak, Redis, OpenBao, mocki), JDK 25 i Dockera.

```bash
./mvnw -B package -DskipTests
export JAVA_HOME=/opt/homebrew/Cellar/openjdk@25/25.0.4.1/libexec/openjdk.jdk/Contents/Home
export MCP_PLATFORM_DEV=/ścieżka/do/mcp-platform-dev     # domyślnie ../mcp-platform-dev obok tego repo
scripts/run-dev-host.sh                                  # https://localhost:18710
```

Skrypt:

- Startuje własny PostgreSQL w kontenerze `mcp-broker-host-pg-18711` (port 18711, hasło losowe na ten start) i usuwa go
  przy wyjściu. Z bazą stosu (`localhost:15432/broker`) się nie łączy: migracje brokera (V3) nie mogą trafić do bazy,
  którą współdzieli obraz brokera ze stosu. Własną bazę podaje się przez `MCP_DB_URL`, `MCP_DB_USER`, `MCP_DB_PASSWORD`
  (wtedy kontener nie powstaje).
- Słucha na `MCP_BROKER_PORT` (domyślnie 18710; zakres brokera w fali M2 to 18710-18719, port 18100 zajmuje broker ze
  stosu). Zajęty port kończy start z komunikatem.
- Sekrety i certyfikaty bierze z `$MCP_PLATFORM_DEV/.secrets/dev.env` i `certs/` przy starcie, nic nie kopiuje do tego
  repo. Brak katalogu albo pliku daje czytelny błąd z nazwą zmiennej.
- Redis i OpenBao są wspólne ze stosem (klucze `broker:*`, `jti:mcp-credential-broker:*`, ścieżki
  `secret/mcp/connections/...` z unikalną wersją), więc nie kolidują z brokerem ze stosu.
- Bez `MCP_GATEWAY_JWKS_URI` używa testowego JWKS z `../mcp-contracts/test-vectors/keys/test-gateway-jwks.json` i
  ustawia `MCP_ALLOW_TEST_KEYS=true`, żeby `resolve` dało się wywołać tokenem podpisanym kluczem testowym A
  (`test-gateway-jwt-a`). To tylko do pracy lokalnej.
- OpenSearch jako `token-exchange` (opcjonalnie): `MCP_OPENSEARCH_EXCHANGE=true`; wymiana w Keycloaku stosu klientem `mcp-credential-broker`
  (`audience=opensearch`, `scope=opensearch-audience`), sekret klienta z OpenBao `secret/mcp/oauth-clients/opensearch`, a gdy go tam nie ma, z
  `KC_CLIENT_MCP_CREDENTIAL_BROKER_SECRET` (zapas dla developmentu). Service Desk jako `service-account`: `MCP_SERVICEDESK_ACCOUNT=true`; klucz musi być w OpenBao
  pod `secret/mcp/service-accounts/servicedesk` (pole `value`).
- GitLab (opcjonalnie): `MCP_GITLAB_URL=http://localhost:18741` (mock ze stosu). `client_secret` broker czyta z OpenBao
  (`secret/mcp/oauth-clients/gitlab`); `MCP_GITLAB_CLIENT_SECRET` to zapas wyłącznie dla developmentu.

Szybkie sprawdzenie (z drugiego terminala; broker wymaga mTLS, więc zdrowie sprawdza się certyfikatem klienta z CA stosu):

```bash
d=$MCP_PLATFORM_DEV/certs
curl -s --cacert $d/ca/ca.crt --cert $d/mcp-gateway/tls.crt --key $d/mcp-gateway/tls.key \
  https://localhost:18710/actuator/health                                   # "status":"UP"
curl -s -o /dev/null -w '%{http_code}\n' --cacert $d/ca/ca.crt -X POST \
  https://localhost:18710/v1/credentials/resolve                            # bez certyfikatu: błąd TLS, kod 000
```

## CI

`ci/run.sh` (`make ci`) jest jedynym punktem wejścia: `verify` (kontrole stylu, `mvnw clean verify`, zero testów = błąd), `hygiene`, `image`
(obraz `mcp-credential-broker:m5-<sha>` z czystego drzewa). `ci/Dockerfile` daje obraz z JDK 25; testy potrzebują gniazda Dockera i wolnych portów
18712-18717. `.gitlab-ci.yml`, `Jenkinsfile` i `.github/workflows/ci.yml` tylko wołają ten skrypt.

Zaufanie do kodu: pełny `verify` (kontenery testowe, gniazdo Dockera, dane dostępowe do rejestru Maven) uruchamia się wyłącznie dla gałęzi
głównej, na dedykowanym agencie (`docker-dedicated`). Zmiana z MR dostaje `ci/run.sh unit` (testy bez kontenerów), bez gniazda i bez
poświadczeń, offline z cache (`MCP_MAVEN_OFFLINE=true`). W GitLabie zmienne `MCP_MAVEN_REPOSITORY_*` muszą być "masked" i "protected";
skrypt używa `.ci/settings.xml` tylko wtedy, gdy hasło jest ustawione, więc MR bez zmiennych nie wysyła poświadczeń nigdzie. Runner z tagiem `docker-dedicated` musi być oznaczony jako protected (konfiguracja runnera, M6), a zadanie `main` zapisuje też cache `maven-mr`, z którego czyta zadanie MR. W GitHub Actions
workflow startuje tylko z `push` na `main` (bez `pull_request`, bo sekrety i Docker są dostępne tylko dla zaufanego kodu). Sekrety GitHub są w Environment `ci-main`. Cache GitLaba dla MR ma osobny klucz i `policy: pull`, a zadanie MR ma tag
`isolated-no-docker`. Jenkins: gałąź w `Jenkinsfile` nie egzekwuje granicy sama (kto zmienia plik, zmienia warunki), więc
poświadczenia i agent z gniazdem Dockera muszą być ograniczone w konfiguracji Jenkinsa do zadania z `main`; reszta izolacji runnerów to M6. Kontrole
stylu czytają nazwy plików przez `<<>>`, więc nazwa pliku nie wykonuje polecenia.

## Struktura

```
pl.aiwcorpo.mcp.broker
├── auth/        mTLS CN, weryfikacja C2 i tokenu BFF, tabela operacji, jti w Redis
├── api/         kontrolery C4, DTO, mapowanie błędów
├── credential/  CredentialService (resolve czterech typów, PUT secret), OAuthService (start, complete, odświeżanie), OffboardingService (purge, czyszczenie), metadane połączeń (JDBC)
├── oauth/       przepływy w Redisie (jednorazowe), blokada odświeżania, limity (RateLimiter)
├── authenticator/ TOTP (RFC 6238), serwis rejestracji i weryfikacji, magazyn ziarna w OpenBao Transit, metadane (JDBC)
├── secret/      SecretStore + OpenBao (AppRole, KV v2, Transit), klucze kont serwisowych, SecretValue
├── system/      SystemRegistry, SystemAdapter (whoami), OAuthProvider, TokenExchanger, ServiceAccountSource, adaptery: AtlassianDc, GitLab, OpenSearch, GenericRest
├── audit/       zdarzenia C8
└── event/       credential.invalidated (Redis pub/sub)
```

Nowe typy poświadczeń wchodzą w `CredentialType` i `SystemRegistry`, nowe operacje w `Operation` (test kontraktowy pilnuje zgodności z OpenAPI).
