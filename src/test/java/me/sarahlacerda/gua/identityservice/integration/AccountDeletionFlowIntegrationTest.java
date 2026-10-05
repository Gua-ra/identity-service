package me.sarahlacerda.gua.identityservice.integration;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.notFound;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.account.AccountGenesisService;

/**
 * Account deletion over real HTTP against Postgres and Redis: the authentication service's notice at
 * {@code POST /oauth2/account-deleted}, and what the deleted account's number, username, sessions, codes
 * and tokens can and cannot do afterwards. Accounts are created the only way they are created, through
 * the interactive sign-in, with the OTP read from Redis.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class AccountDeletionFlowIntegrationTest {

    private static final String APP_CLIENT = "gua-ios";
    private static final String APP_REDIRECT = "global.gua:/oidc";
    /** Carries characters that RFC 6749 form-encodes inside a Basic header. */
    private static final String MAS_SECRET = "mas+test/secret=";
    private static final String LOGIN_UI = "/signin";
    private static final String LOGIN_COOKIE = "gua_login";
    private static final Pattern LOGIN_COOKIE_VALUE = Pattern.compile(LOGIN_COOKIE + "=([^;]+)");
    private static final String PIN = "739164";

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
            .withDatabaseName("identity")
            .withUsername("identity")
            .withPassword("identity");

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    static WireMockServer synapse;

    @BeforeAll
    static void startSynapse() {
        synapse = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        synapse.start();
    }

    @AfterAll
    static void stopSynapse() {
        if (synapse != null) {
            synapse.stop();
        }
    }

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379).toString());

        registry.add("identity.matrix.admin-api-base-url", () -> synapse.baseUrl());
        registry.add("identity.matrix.client-api-base-url", () -> synapse.baseUrl());
        registry.add("identity.matrix.homeserver-domain", () -> "example.com");
        registry.add("identity.matrix.admin-access-token", () -> "test-admin-token");
        registry.add("identity.directory.pepper", () -> "test-pepper");
        registry.add("identity.sms.twilio.enabled", () -> "false");
        registry.add("identity.rate-limits.enabled", () -> "false");

        registry.add("oidc.issuer", () -> "http://localhost");
        // The application.yml placeholder for the mas client's secret: with it set, mas is confidential.
        // Its homeserver ids keep the application.yml default, the legacy single homeserver.
        registry.add("OIDC_CLIENT_MAS_SECRET", () -> MAS_SECRET);
        registry.add("oidc.account-deletion-notices-enabled", () -> "true");
        registry.add("idp.login.ui-url", () -> LOGIN_UI);
        registry.add("idp.login.cookie-name", () -> LOGIN_COOKIE);
        registry.add("idp.login.registration.web-allowlist-enabled", () -> "false");
    }

    @LocalServerPort
    int port;

    @Autowired
    StringRedisTemplate redisTemplate;

    @Autowired
    DirectoryService directoryService;

    @Autowired
    AccountGenesisService genesisService;

    private RestTemplate http;
    private String baseUrl;

    @BeforeEach
    void setUp() {
        // The JDK client follows no redirect and, unlike HttpURLConnection, hands back the body of a 401
        // that carries WWW-Authenticate.
        http = new RestTemplate(new org.springframework.http.client.JdkClientHttpRequestFactory(
                java.net.http.HttpClient.newBuilder().followRedirects(java.net.http.HttpClient.Redirect.NEVER).build()));
        http.setErrorHandler(new org.springframework.web.client.DefaultResponseErrorHandler() {
            @Override
            public boolean hasError(org.springframework.http.client.ClientHttpResponse response) {
                return false;
            }
        });
        baseUrl = "http://localhost:" + port;

        // The homeserver knows none of these numbers or usernames.
        synapse.resetAll();
        synapse.stubFor(get(urlPathMatching("/_synapse/admin/v1/threepid/msisdn/users/.*")).willReturn(notFound()));
        synapse.stubFor(get(urlPathMatching("/_synapse/admin/v2/users/.*")).willReturn(notFound()));
    }

    // --- The notice -----------------------------------------------------------------

    @Test
    void theNoticeIsRefusedUnlessTheConfidentialClientSendsIt() {
        String victim = seedAccount();

        assertThat(notify(form(victim, null, null), null).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(notify(form(victim, APP_CLIENT, null), null).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(notify(form(victim, null, null), basic(APP_CLIENT, "")).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(notify(form(victim, APP_CLIENT, "anything"), null).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(notify(form(victim, "mas", "wrong"), null).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(notify(form(victim, null, null), basic("mas", "wrong")).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        ResponseEntity<Map> unknown = notify(form(victim, "no-such-client", MAS_SECRET), null);
        assertThat(unknown.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(unknown.getBody()).containsEntry("code", "invalid_client");

        assertThat(directoryService.findByUserId(victim)).hasSize(1);
        assertThat(genesisService.isDeleted(victim)).isFalse();
    }

    @Test
    void theNoticeIsRefusedForASubThatIsNotAUserOnThisDeployment() {
        for (String sub : new String[] { null, "", "alice", "@alice", "@alice:elsewhere.example",
                "@al ice:example.com" }) {
            ResponseEntity<Map> response = notify(form(sub, "mas", MAS_SECRET), null);
            assertThat(response.getStatusCode()).as("sub %s", sub).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody()).as("sub %s", sub).containsEntry("code", "invalid_request");
        }
    }

    @Test
    void theNoticeIsAcceptedWithEitherClientAuthenticationMethodAndRepeatsHarmlessly() {
        String byPost = seedAccount();
        String byBasic = seedAccount();

        assertThat(notify(form(byPost, "mas", MAS_SECRET), null).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(notify(form(byBasic, null, null), basic("mas", MAS_SECRET)).getStatusCode())
                .isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(notify(form(byPost, "mas", MAS_SECRET), null).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        for (String userId : List.of(byPost, byBasic)) {
            assertThat(directoryService.findByUserId(userId)).isEmpty();
            assertThat(genesisService.isDeleted(userId)).isTrue();
        }
    }

    // --- After the deletion ---------------------------------------------------------

    @Test
    void afterADeletionTheNumberStartsOverTheUsernameStaysReservedAndNothingFromBeforeWorks() throws Exception {
        String phone = "+16042260101";
        String username = handle("del");

        // An account, and a friend who can find it by its number.
        SignedIn account = signUp(phone, username);
        SignedIn friend = signUp("+16042260102", handle("fr"));
        assertThat(account.userId()).isEqualTo("@" + username + ":example.com");
        assertThat(lookup(friend.accessToken(), phone)).hasSize(1);
        assertThat(bearerGet(account.accessToken(), "/userinfo").getStatusCode()).isEqualTo(HttpStatus.OK);

        // Begun before the deletion: a sign-in parked at the PIN, and a code nobody has redeemed yet.
        LoginClient parked = startAuthorize(s256(randomVerifier()), "state-parked");
        parked.post("/login/phone", Map.of("phoneNumber", phone));
        assertThat(parked.post("/login/otp", Map.of("code", readOtp(phone))).get("phase")).isEqualTo("PIN_REQUIRED");
        String verifier = randomVerifier();
        URI unredeemed = signIn(phone, s256(verifier), "state-code", null, PIN);

        assertThat(notify(form(account.userId(), "mas", MAS_SECRET), null).getStatusCode())
                .isEqualTo(HttpStatus.NO_CONTENT);

        ResponseEntity<Map> parkedAfter = parked.getRaw("/login/context");
        assertThat(parkedAfter.getStatusCode()).isEqualTo(HttpStatus.GONE);
        assertThat(parkedAfter.getBody()).containsEntry("code", "account_deleted");
        ResponseEntity<Map> exchange = exchangeCode(parseQuery(unredeemed).get("code"), verifier);
        assertThat(exchange.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(exchange.getBody()).containsEntry("code", "invalid_grant");
        assertThat(bearerGet(account.accessToken(), "/userinfo").getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(bearerGet(account.accessToken(), "/security/pin/status").getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(lookup(friend.accessToken(), phone)).isEmpty();

        // The same number reaches the username step of a new account.
        String freshVerifier = randomVerifier();
        LoginClient fresh = startAuthorize(s256(freshVerifier), "state-fresh");
        fresh.post("/login/phone", Map.of("phoneNumber", phone));
        assertThat(fresh.post("/login/otp", Map.of("code", readOtp(phone))).get("phase")).isEqualTo("PROFILE_REQUIRED");

        // The old username is refused on every path that can claim one.
        ResponseEntity<Map> profile = fresh.postRaw("/login/profile",
                Map.of("username", username, "displayName", "Someone Else"));
        assertThat(profile.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(profile.getBody()).containsEntry("code", "username_taken");
        ResponseEntity<Map> check = http.exchange(baseUrl + "/signup/check-username?username=" + username,
                HttpMethod.GET, new HttpEntity<>(jsonHeaders()), Map.class);
        assertThat(check.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(check.getBody()).containsEntry("available", false);
        assertThat(restSignupStatus(phone, username)).isEqualTo(HttpStatus.CONFLICT);

        // A new username finishes a new account, under a new subject.
        Map<?, ?> state = fresh.post("/login/profile", Map.of("username", handle("new"), "displayName", "New"));
        URI redirect = fresh.driveToCode(state, PIN, null);
        String newSubject = SignedJWT.parse((String) exchangeCode(parseQuery(redirect).get("code"), freshVerifier)
                .getBody().get("access_token")).getJWTClaimsSet().getSubject();
        assertThat(newSubject).isNotEqualTo(account.userId());
    }

    // --- Helpers --------------------------------------------------------------------

    private record SignedIn(String userId, String accessToken) {
    }

    /** A directory row the way a signup leaves one, without spending an OTP. */
    private String seedAccount() {
        String userId = "@" + handle("seed") + ":example.com";
        directoryService.upsertByDigest(UUID.randomUUID().toString(), userId, "Seeded");
        return userId;
    }

    private static String handle(String prefix) {
        return prefix + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
    }

    private SignedIn signUp(String phone, String username) throws Exception {
        String verifier = randomVerifier();
        LoginClient login = startAuthorize(s256(verifier), "state-signup");
        login.post("/login/phone", Map.of("phoneNumber", phone));
        Map<?, ?> state = login.post("/login/otp", Map.of("code", readOtp(phone)));
        assertThat(state.get("phase")).isEqualTo("PROFILE_REQUIRED");
        state = login.post("/login/profile", Map.of("username", username, "displayName", "Display"));
        URI redirect = login.driveToCode(state, PIN, null);
        String accessToken = (String) exchangeCode(parseQuery(redirect).get("code"), verifier).getBody()
                .get("access_token");
        return new SignedIn(SignedJWT.parse(accessToken).getJWTClaimsSet().getSubject(), accessToken);
    }

    private URI signIn(String phone, String challenge, String state, String pinToSetUp, String existingPin) {
        LoginClient login = startAuthorize(challenge, state);
        login.post("/login/phone", Map.of("phoneNumber", phone));
        Map<?, ?> current = login.post("/login/otp", Map.of("code", readOtp(phone)));
        return login.driveToCode(current, pinToSetUp, existingPin);
    }

    private LoginClient startAuthorize(String challenge, String state) {
        String url = baseUrl + "/oauth2/authorize?response_type=code&client_id=" + APP_CLIENT
                + "&redirect_uri=" + encode(APP_REDIRECT) + "&scope=" + encode("openid profile phone")
                + "&state=" + state + "&code_challenge=" + challenge + "&code_challenge_method=S256";
        ResponseEntity<String> response = http.exchange(URI.create(url), HttpMethod.GET, HttpEntity.EMPTY,
                String.class);
        assertThat(response.getStatusCode()).as("authorize: %s", response.getBody()).isEqualTo(HttpStatus.FOUND);
        LoginClient anonymous = new LoginClient(loginCookie(response.getHeaders()), null);
        return new LoginClient(anonymous.cookie, (String) anonymous.get("/login/context").get("csrfToken"));
    }

    /** {@code POST /signup/complete} on the REST path, through its own OTP, for this username. */
    private HttpStatus restSignupStatus(String phone, String username) {
        clearOtpBudgets();
        ResponseEntity<Void> sent = http.exchange(baseUrl + "/otp/send", HttpMethod.POST,
                new HttpEntity<>(Map.of("phone", phone), jsonHeaders()), Void.class);
        assertThat(sent.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        ResponseEntity<Map> verified = http.exchange(baseUrl + "/otp/verify", HttpMethod.POST,
                new HttpEntity<>(Map.of("phone", phone, "code", readOtp(phone)), jsonHeaders()),
                Map.class);
        assertThat(verified.getStatusCode()).as("verify: %s", verified.getBody()).isEqualTo(HttpStatus.OK);
        String signupToken = (String) verified.getBody().get("signupToken");
        assertThat(signupToken).isNotBlank();
        ResponseEntity<Map> completed = http.exchange(baseUrl + "/signup/complete", HttpMethod.POST,
                new HttpEntity<>(Map.of("signupToken", signupToken, "username", username,
                        "displayName", "Someone Else", "pin", PIN), jsonHeaders()),
                Map.class);
        return HttpStatus.valueOf(completed.getStatusCode().value());
    }

    private ResponseEntity<Map> notify(MultiValueMap<String, String> form, String authorization) {
        HttpHeaders headers = jsonHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        if (authorization != null) {
            headers.set(HttpHeaders.AUTHORIZATION, authorization);
        }
        return http.exchange(baseUrl + "/oauth2/account-deleted", HttpMethod.POST, new HttpEntity<>(form, headers),
                Map.class);
    }

    private static MultiValueMap<String, String> form(String sub, String clientId, String clientSecret) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        if (sub != null) {
            form.add("sub", sub);
        }
        if (clientId != null) {
            form.add("client_id", clientId);
        }
        if (clientSecret != null) {
            form.add("client_secret", clientSecret);
        }
        return form;
    }

    /** client_secret_basic as MAS sends it: both parts form-urlencoded, then base64. */
    private static String basic(String clientId, String clientSecret) {
        String pair = encode(clientId) + ":" + encode(clientSecret);
        return "Basic " + Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8));
    }

    private List<?> lookup(String accessToken, String phone) {
        HttpHeaders headers = jsonHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(accessToken);
        ResponseEntity<Map> response = http.exchange(baseUrl + "/directory/lookup", HttpMethod.POST,
                new HttpEntity<>(Map.of("phones", List.of(phone)), headers), Map.class);
        assertThat(response.getStatusCode()).as("lookup: %s", response.getBody()).isEqualTo(HttpStatus.OK);
        return (List<?>) response.getBody().get("matches");
    }

    private ResponseEntity<Map> bearerGet(String accessToken, String path) {
        HttpHeaders headers = jsonHeaders();
        headers.setBearerAuth(accessToken);
        return http.exchange(baseUrl + path, HttpMethod.GET, new HttpEntity<>(headers), Map.class);
    }

    private ResponseEntity<Map> exchangeCode(String code, String verifier) {
        HttpHeaders headers = jsonHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", APP_REDIRECT);
        form.add("client_id", APP_CLIENT);
        form.add("code_verifier", verifier);
        return http.exchange(baseUrl + "/oauth2/token", HttpMethod.POST, new HttpEntity<>(form, headers), Map.class);
    }

    private String readOtp(String phone) {
        String code = redisTemplate.opsForValue().get("otp:code:" + phone);
        assertThat(code).as("OTP for %s", phone).isNotBlank();
        return code;
    }

    /**
     * Every call here comes from localhost and these flows send more codes to one number than a person
     * would in an hour, so the send budgets are cleared before each code is sent.
     */
    private void clearOtpBudgets() {
        Set<String> budgets = redisTemplate.keys("otp:rate:*");
        if (budgets != null && !budgets.isEmpty()) {
            redisTemplate.delete(budgets);
        }
    }

    private static HttpHeaders jsonHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        return headers;
    }

    private static String loginCookie(HttpHeaders headers) {
        for (String header : headers.getOrEmpty(HttpHeaders.SET_COOKIE)) {
            Matcher matcher = LOGIN_COOKIE_VALUE.matcher(header);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }
        throw new AssertionError("No " + LOGIN_COOKIE + " cookie");
    }

    private static Map<String, String> parseQuery(URI uri) {
        Map<String, String> result = new LinkedHashMap<>();
        for (String pair : uri.getRawQuery().split("&")) {
            int eq = pair.indexOf('=');
            result.put(pair.substring(0, eq), java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return result;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String randomVerifier() {
        byte[] bytes = new byte[48];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String s256(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    /** A browser stand-in: holds the login cookie and echoes the CSRF token. */
    private final class LoginClient {
        private final String cookie;
        private final String csrf;

        LoginClient(String cookie, String csrf) {
            this.cookie = cookie;
            this.csrf = csrf;
        }

        Map<?, ?> get(String path) {
            ResponseEntity<Map> response = getRaw(path);
            assertThat(response.getStatusCode()).as("GET %s: %s", path, response.getBody()).isEqualTo(HttpStatus.OK);
            return response.getBody();
        }

        ResponseEntity<Map> getRaw(String path) {
            return http.exchange(baseUrl + path, HttpMethod.GET, new HttpEntity<>(headers()), Map.class);
        }

        Map<?, ?> post(String path, Map<String, ?> body) {
            if ("/login/phone".equals(path)) {
                clearOtpBudgets();
            }
            ResponseEntity<Map> response = postRaw(path, body);
            assertThat(response.getStatusCode()).as("POST %s: %s", path, response.getBody()).isEqualTo(HttpStatus.OK);
            return response.getBody();
        }

        ResponseEntity<Map> postRaw(String path, Map<String, ?> body) {
            HttpHeaders headers = headers();
            headers.setContentType(MediaType.APPLICATION_JSON);
            return http.exchange(baseUrl + path, HttpMethod.POST, new HttpEntity<>(body, headers), Map.class);
        }

        URI driveToCode(Map<?, ?> current, String pinToSetUp, String existingPin) {
            for (int step = 0; step < 6; step++) {
                String phase = (String) current.get("phase");
                switch (phase) {
                    case "PIN_SETUP" -> current = post("/login/pin-setup", Map.of("pin", pinToSetUp));
                    case "PIN_REQUIRED" -> current = post("/login/pin", Map.of("pin", existingPin));
                    case "PASSKEY_SETUP" -> current = post("/login/passkey/setup-skip", Map.of());
                    case "COMPLETED" -> {
                        return URI.create((String) current.get("redirectUrl"));
                    }
                    default -> throw new AssertionError("Unexpected login phase: " + phase);
                }
            }
            throw new AssertionError("Login flow did not complete");
        }

        private HttpHeaders headers() {
            HttpHeaders headers = jsonHeaders();
            headers.add(HttpHeaders.COOKIE, LOGIN_COOKIE + "=" + cookie);
            if (csrf != null) {
                headers.add("X-CSRF-Token", csrf);
            }
            return headers;
        }
    }
}
