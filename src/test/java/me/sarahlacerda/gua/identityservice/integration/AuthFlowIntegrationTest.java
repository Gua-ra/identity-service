package me.sarahlacerda.gua.identityservice.integration;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.notFound;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
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
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;

/**
 * End-to-end OIDC authorization-code flow over real HTTP against Postgres and
 * Redis. Every authorization code is obtained the only way the service issues
 * one: {@code GET /oauth2/authorize} parks a login session, then the
 * {@code /login/**} steps (phone, OTP, PIN or PIN setup, profile, passkey skip)
 * are walked until {@code /login/**} hands back the redirect carrying the code.
 * The OTP is read from the Redis key {@code otp:code:<E.164>} written by
 * {@code OtpService}, so no SMS provider is involved.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class AuthFlowIntegrationTest {

    private static final String CLIENT_ID = "gua-ios";
    private static final String REDIRECT_URI = "global.gua:/oidc";
    private static final String LOGIN_UI = "/signin";
    private static final String LOGIN_COOKIE = "gua_login";
    private static final String CSRF_HEADER = "X-CSRF-Token";
    private static final Pattern LOGIN_COOKIE_VALUE = Pattern.compile(LOGIN_COOKIE + "=([^;]+)");

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
        .withDatabaseName("identity")
        .withUsername("identity")
        .withPassword("identity");

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
        .withExposedPorts(6379);

    static WireMockServer wireMock;

    @BeforeAll
    static void startWireMock() {
        wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        wireMock.start();
    }

    @AfterAll
    static void stopWireMock() {
        if (wireMock != null) wireMock.stop();
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

        registry.add("identity.matrix.admin-api-base-url", () -> wireMock.baseUrl());
        registry.add("identity.matrix.client-api-base-url", () -> wireMock.baseUrl());
        registry.add("identity.matrix.homeserver-domain", () -> "example.com");
        registry.add("identity.matrix.admin-access-token", () -> "test-admin-token");
        registry.add("identity.matrix.user-localpart-prefix", () -> "gua");
        registry.add("identity.directory.pepper", () -> "test-pepper");
        registry.add("identity.sms.twilio.enabled", () -> "false");
        registry.add("identity.rate-limits.enabled", () -> "false");

        registry.add("oidc.issuer", () -> "http://localhost");
        registry.add("idp.login.ui-url", () -> LOGIN_UI);
        registry.add("idp.login.cookie-name", () -> LOGIN_COOKIE);
        // Keep the flow independent of the beta web-allowlist gate.
        registry.add("idp.login.registration.web-allowlist-enabled", () -> "false");
    }

    @LocalServerPort
    int port;

    @Autowired
    StringRedisTemplate redisTemplate;

    @Autowired
    DirectoryService directoryService;

    @Autowired
    PhoneNumberHasher phoneNumberHasher;

    private RestTemplate restTemplate;
    private String baseUrl;

    @BeforeEach
    void setupClient() {
        org.springframework.http.client.SimpleClientHttpRequestFactory factory = new org.springframework.http.client.SimpleClientHttpRequestFactory() {
            @Override
            protected void prepareConnection(java.net.HttpURLConnection connection, String httpMethod) throws java.io.IOException {
                super.prepareConnection(connection, httpMethod);
                connection.setInstanceFollowRedirects(false);
            }
        };
        restTemplate = new RestTemplate(factory);
        restTemplate.setErrorHandler(new org.springframework.web.client.DefaultResponseErrorHandler() {
            @Override
            public boolean hasError(org.springframework.http.client.ClientHttpResponse response) {
                return false;
            }
        });
        baseUrl = "http://localhost:" + port;

        // The homeserver knows none of the phones or usernames used here: the OTP step's
        // pepper-drift fallback finds no bound account and the profile step sees the
        // chosen handle as free.
        wireMock.resetAll();
        wireMock.stubFor(get(urlPathMatching("/_synapse/admin/v1/threepid/msisdn/users/.*"))
                .willReturn(notFound()));
        wireMock.stubFor(get(urlPathMatching("/_synapse/admin/v2/users/.*"))
                .willReturn(notFound()));
    }

    @Test
    void fullPkceAuthorizationCodeFlowIssuesRs256AccessTokenAndReturnsUserInfo() throws Exception {
        String phone = "+16042250001";
        String verifier = randomVerifier();
        String challenge = s256(verifier);
        String state = UUID.randomUUID().toString();

        // 1. Obtain the code through the interactive flow (new user: profile + PIN setup skipped).
        URI redirect = signInInteractively(phone, challenge, state, null, null);
        assertThat(redirect.toString()).startsWith(REDIRECT_URI);
        Map<String, String> query = parseQuery(redirect);
        assertThat(query.get("state")).isEqualTo(state);
        String code = query.get("code");
        assertThat(code).isNotBlank();

        // 2. Exchange code for tokens with verifier
        ResponseEntity<Map> tokenResponse = exchangeCode(code, verifier);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> body = tokenResponse.getBody();
        assertThat(body).isNotNull();
        String accessToken = (String) body.get("access_token");
        String idToken = (String) body.get("id_token");
        assertThat(accessToken).isNotBlank();
        assertThat(idToken).isNotBlank();
        assertThat(body.get("token_type")).isEqualTo("Bearer");

        // 3. Validate access token signature with public JWKS
        SignedJWT signedAccess = SignedJWT.parse(accessToken);
        assertThat(signedAccess.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        RSAKey publicKey = fetchSigningKey();
        assertThat(signedAccess.verify(new RSASSAVerifier(publicKey.toRSAPublicKey()))).isTrue();
        JWTClaimsSet claims = signedAccess.getJWTClaimsSet();
        assertThat(claims.getSubject()).isNotBlank();
        assertThat(claims.getAudience()).contains(CLIENT_ID);

        // 4. Call /userinfo
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        ResponseEntity<Map> userInfo = restTemplate.exchange(
            baseUrl + "/userinfo",
            HttpMethod.GET,
            new HttpEntity<>(headers),
            Map.class
        );
        assertThat(userInfo.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(userInfo.getBody()).containsEntry("phone_number", phone);
        assertThat(userInfo.getBody()).containsEntry("sub", claims.getSubject());
    }

    @Test
    void replayingAuthorizationCodeIsRejected() throws Exception {
        String phone = "+16042250002";
        String verifier = randomVerifier();
        String challenge = s256(verifier);

        String code = parseQuery(signInInteractively(phone, challenge, "state-x", null, null)).get("code");

        ResponseEntity<Map> first = exchangeCode(code, verifier);
        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<Map> second = exchangeCode(code, verifier);
        assertThat(second.getStatusCode()).isEqualTo(BAD_REQUEST);
        assertThat(second.getBody()).containsEntry("code", "invalid_grant");
    }

    @Test
    void mismatchedPkceVerifierIsRejected() throws Exception {
        String phone = "+16042250003";
        String verifier = randomVerifier();
        String wrongVerifier = randomVerifier();
        String challenge = s256(verifier);

        String code = parseQuery(signInInteractively(phone, challenge, "state-y", null, null)).get("code");

        ResponseEntity<Map> response = exchangeCode(code, wrongVerifier);
        assertThat(response.getStatusCode()).isEqualTo(BAD_REQUEST);
        assertThat(response.getBody()).containsEntry("code", "invalid_grant");
    }

    @Test
    void publicClientRejectedWhenPkceMissing() {
        StringBuilder sb = new StringBuilder(baseUrl).append("/oauth2/authorize?");
        appendParam(sb, "response_type", "code");
        appendParam(sb, "client_id", CLIENT_ID);
        appendParam(sb, "redirect_uri", REDIRECT_URI);
        appendParam(sb, "scope", "openid profile");
        sb.setLength(sb.length() - 1);
        ResponseEntity<Map> response = restTemplate.exchange(URI.create(sb.toString()), HttpMethod.GET,
                HttpEntity.EMPTY, Map.class);
        assertThat(response.getStatusCode()).isEqualTo(BAD_REQUEST);
        assertThat(response.getBody()).containsEntry("code", "invalid_request");
        assertThat(response.getHeaders().getFirst(HttpHeaders.SET_COOKIE)).isNull();
    }

    @Test
    void unknownClientIdReturnsInvalidClient() {
        StringBuilder sb = new StringBuilder(baseUrl).append("/oauth2/authorize?");
        appendParam(sb, "response_type", "code");
        appendParam(sb, "client_id", "no-such-client");
        appendParam(sb, "redirect_uri", REDIRECT_URI);
        appendParam(sb, "scope", "openid");
        sb.setLength(sb.length() - 1);
        ResponseEntity<Map> response = restTemplate.exchange(URI.create(sb.toString()), HttpMethod.GET,
                HttpEntity.EMPTY, Map.class);
        assertThat(response.getStatusCode()).isEqualTo(BAD_REQUEST);
        assertThat(response.getBody()).containsEntry("code", "invalid_client");
        assertThat(response.getHeaders().getFirst(HttpHeaders.SET_COOKIE)).isNull();
    }

    /**
     * A returning account with two-step verification enabled must present its PIN
     * after the OTP: the OTP alone moves the session to PIN_REQUIRED and nothing
     * short of the PIN advances it, so an SMS channel alone never yields a code.
     */
    @Test
    void returningUserWithPinMustPresentItBeforeCodeIsIssued() throws Exception {
        String phone = "+16042250004";
        String pin = "482913";

        // First login: brand-new account that opts into a PIN during PIN setup.
        String firstVerifier = randomVerifier();
        String firstCode = parseQuery(signInInteractively(phone, s256(firstVerifier), "state-p1", pin, null))
                .get("code");
        String firstSubject = subjectOf(exchangeCode(firstCode, firstVerifier));

        // Second login for the same phone: OTP alone stops at PIN_REQUIRED.
        String secondVerifier = randomVerifier();
        LoginClient login = startAuthorize(s256(secondVerifier), "state-p2");
        Map<?, ?> state = login.post("/login/phone", Map.of("phoneNumber", phone));
        assertThat(state.get("phase")).isEqualTo("OTP_SENT");
        state = login.post("/login/otp", Map.of("code", readOtpFromRedis(phone)));
        assertThat(state.get("phase")).isEqualTo("PIN_REQUIRED");
        assertThat(state.get("redirectUrl")).isNull();

        // Trying to finish without the PIN is refused by the phase machine.
        ResponseEntity<Map> skip = login.postRaw("/login/passkey/setup-skip", Map.of());
        assertThat(skip.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(skip.getBody()).containsEntry("code", "unexpected_step");

        // A wrong PIN is refused and does not advance the session.
        ResponseEntity<Map> wrongPin = login.postRaw("/login/pin", Map.of("pin", "735182"));
        assertThat(wrongPin.getStatusCode()).isEqualTo(BAD_REQUEST);
        assertThat(wrongPin.getBody()).containsEntry("code", "invalid_pin");
        assertThat(login.get("/login/context").get("phase")).isEqualTo("PIN_REQUIRED");

        // The real PIN completes the login and the code exchanges for the same subject.
        state = login.post("/login/pin", Map.of("pin", pin));
        URI redirect = login.driveToCode(state, null, null);
        Map<String, String> query = parseQuery(redirect);
        assertThat(query.get("state")).isEqualTo("state-p2");
        assertThat(subjectOf(exchangeCode(query.get("code"), secondVerifier))).isEqualTo(firstSubject);
    }

    /**
     * Regression for ADM-001 L1a: the removed non-interactive branch of
     * {@code GET /oauth2/authorize} accepted {@code phone_number} and
     * {@code otp_code} as query parameters, verified the OTP, auto-provisioned an
     * account and redirected back to the client with a code. The same URL must now
     * be treated exactly like an interactive request: redirect to the login UI with
     * a parked session at the phone step, the OTP left untouched, no account
     * created and no authorization code minted.
     */
    @Test
    void legacyOtpQueryParametersNeverYieldAnAuthorizationCode() throws Exception {
        String phone = "+16042250005";
        sendOtpViaRestEndpoint(phone);
        String otp = readOtpFromRedis(phone);
        assertThat(otp).isNotBlank();
        long codesBefore = authorizationCodeCount();

        StringBuilder sb = new StringBuilder(baseUrl).append("/oauth2/authorize?");
        appendParam(sb, "response_type", "code");
        appendParam(sb, "client_id", CLIENT_ID);
        appendParam(sb, "redirect_uri", REDIRECT_URI);
        appendParam(sb, "scope", "openid profile phone");
        appendParam(sb, "phone_number", phone);
        appendParam(sb, "otp_code", otp);
        appendParam(sb, "display_name", "Legacy Caller");
        appendParam(sb, "state", "state-legacy");
        appendParam(sb, "code_challenge", s256(randomVerifier()));
        appendParam(sb, "code_challenge_method", "S256");
        sb.setLength(sb.length() - 1);

        ResponseEntity<String> response = restTemplate.exchange(URI.create(sb.toString()), HttpMethod.GET,
                HttpEntity.EMPTY, String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        URI location = response.getHeaders().getLocation();
        assertThat(location).isNotNull();
        assertThat(location.toString()).isEqualTo(LOGIN_UI);
        assertThat(location.toString()).doesNotContain("code=").doesNotStartWith(REDIRECT_URI);

        // The parked session is a plain interactive session at the phone step.
        String cookie = loginCookie(response.getHeaders());
        LoginClient login = new LoginClient(cookie, null);
        Map<?, ?> context = login.get("/login/context");
        assertThat(context.get("phase")).isEqualTo("PHONE");
        assertThat(context.get("maskedPhone")).isNull();
        assertThat(context.get("redirectUrl")).isNull();

        // Nothing happened on the server side: OTP not consumed, no account, no code.
        assertThat(readOtpFromRedis(phone)).isEqualTo(otp);
        assertThat(directoryService.findByDigest(phoneNumberHasher.digest(phone))).isEmpty();
        assertThat(authorizationCodeCount()).isEqualTo(codesBefore);
    }

    // --- Interactive flow driver ------------------------------------------------

    /**
     * Walks the whole interactive flow for {@code phone} and returns the redirect
     * (back to the client) carrying the authorization code. {@code pinToSetUp} is
     * chosen at PIN setup for a new account (null skips); {@code existingPin} is
     * presented at the PIN step for a returning account.
     */
    private URI signInInteractively(String phone, String challenge, String state, String pinToSetUp,
            String existingPin) {
        LoginClient login = startAuthorize(challenge, state);
        Map<?, ?> current = login.post("/login/phone", Map.of("phoneNumber", phone));
        assertThat(current.get("phase")).isEqualTo("OTP_SENT");
        String otp = readOtpFromRedis(phone);
        assertThat(otp).isNotBlank();
        current = login.post("/login/otp", Map.of("code", otp));
        return login.driveToCode(current, pinToSetUp, existingPin);
    }

    /** GET /oauth2/authorize interactively and bind a client to the parked session. */
    private LoginClient startAuthorize(String challenge, String state) {
        StringBuilder sb = new StringBuilder(baseUrl).append("/oauth2/authorize?");
        appendParam(sb, "response_type", "code");
        appendParam(sb, "client_id", CLIENT_ID);
        appendParam(sb, "redirect_uri", REDIRECT_URI);
        appendParam(sb, "scope", "openid profile phone");
        appendParam(sb, "state", state);
        appendParam(sb, "code_challenge", challenge);
        appendParam(sb, "code_challenge_method", "S256");
        sb.setLength(sb.length() - 1);

        ResponseEntity<String> response = restTemplate.exchange(URI.create(sb.toString()), HttpMethod.GET,
                HttpEntity.EMPTY, String.class);
        assertThat(response.getStatusCode())
                .as("authorize response body: %s", response.getBody())
                .isEqualTo(HttpStatus.FOUND);
        assertThat(response.getHeaders().getLocation()).hasToString(LOGIN_UI);

        LoginClient login = new LoginClient(loginCookie(response.getHeaders()), null);
        Map<?, ?> context = login.get("/login/context");
        assertThat(context.get("phase")).isEqualTo("PHONE");
        String csrf = (String) context.get("csrfToken");
        assertThat(csrf).isNotBlank();
        return new LoginClient(login.cookie, csrf);
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
            ResponseEntity<Map> response = restTemplate.exchange(baseUrl + path, HttpMethod.GET,
                    new HttpEntity<>(headers()), Map.class);
            assertThat(response.getStatusCode()).as("GET %s: %s", path, response.getBody()).isEqualTo(HttpStatus.OK);
            return response.getBody();
        }

        Map<?, ?> post(String path, Map<String, ?> body) {
            ResponseEntity<Map> response = postRaw(path, body);
            assertThat(response.getStatusCode()).as("POST %s: %s", path, response.getBody()).isEqualTo(HttpStatus.OK);
            return response.getBody();
        }

        ResponseEntity<Map> postRaw(String path, Map<String, ?> body) {
            HttpHeaders headers = headers();
            headers.setContentType(MediaType.APPLICATION_JSON);
            return restTemplate.exchange(baseUrl + path, HttpMethod.POST, new HttpEntity<>(body, headers), Map.class);
        }

        /** Advances the session step by step until the code-bearing redirect is handed back. */
        URI driveToCode(Map<?, ?> current, String pinToSetUp, String existingPin) {
            for (int step = 0; step < 6; step++) {
                String phase = (String) current.get("phase");
                switch (phase) {
                    case "PROFILE_REQUIRED" -> current = post("/login/profile",
                            Map.of("username", "it" + UUID.randomUUID().toString().replace("-", "").substring(0, 10),
                                    "displayName", "Integration User"));
                    case "PIN_SETUP" -> current = post("/login/pin-setup",
                            pinToSetUp == null ? Map.of("skip", true) : Map.of("pin", pinToSetUp, "skip", false));
                    case "PIN_REQUIRED" -> {
                        assertThat(existingPin).as("account requires a PIN but none was supplied").isNotNull();
                        current = post("/login/pin", Map.of("pin", existingPin));
                    }
                    case "PASSKEY_SETUP" -> current = post("/login/passkey/setup-skip", Map.of());
                    case "COMPLETED" -> {
                        String redirectUrl = (String) current.get("redirectUrl");
                        assertThat(redirectUrl).isNotBlank();
                        return URI.create(redirectUrl);
                    }
                    default -> throw new AssertionError("Unexpected login phase: " + phase);
                }
            }
            throw new AssertionError("Login flow did not complete within the expected number of steps");
        }

        private HttpHeaders headers() {
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.COOKIE, LOGIN_COOKIE + "=" + cookie);
            if (csrf != null) {
                headers.add(CSRF_HEADER, csrf);
            }
            return headers;
        }
    }

    // --- Helpers ----------------------------------------------------------------

    private static String loginCookie(HttpHeaders headers) {
        List<String> setCookies = headers.get(HttpHeaders.SET_COOKIE);
        assertThat(setCookies).as("Set-Cookie").isNotNull();
        for (String header : setCookies) {
            Matcher matcher = LOGIN_COOKIE_VALUE.matcher(header);
            if (matcher.find()) {
                assertThat(header).contains("HttpOnly").contains("SameSite=Lax");
                return matcher.group(1);
            }
        }
        throw new AssertionError("No " + LOGIN_COOKIE + " cookie in " + setCookies);
    }

    /** The REST OTP endpoint shares the same Redis key space as the interactive flow. */
    private void sendOtpViaRestEndpoint(String phone) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        String body = "{\"phone\":\"" + phone + "\"}";
        ResponseEntity<Void> response = restTemplate.exchange(
            baseUrl + "/otp/send",
            HttpMethod.POST,
            new HttpEntity<>(body, headers),
            Void.class
        );
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
    }

    private String readOtpFromRedis(String phone) {
        return redisTemplate.opsForValue().get("otp:code:" + phone);
    }

    private long authorizationCodeCount() {
        var keys = redisTemplate.keys("oidc:code:*");
        return keys == null ? 0 : keys.size();
    }

    private static void appendParam(StringBuilder sb, String name, String value) {
        sb.append(name).append('=').append(java.net.URLEncoder.encode(value, StandardCharsets.UTF_8)).append('&');
    }

    private ResponseEntity<Map> exchangeCode(String code, String verifier) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", REDIRECT_URI);
        form.add("client_id", CLIENT_ID);
        form.add("code_verifier", verifier);
        return restTemplate.exchange(
            baseUrl + "/oauth2/token",
            HttpMethod.POST,
            new HttpEntity<>(form, headers),
            Map.class
        );
    }

    private static String subjectOf(ResponseEntity<Map> tokenResponse) throws Exception {
        assertThat(tokenResponse.getStatusCode()).as("token response: %s", tokenResponse.getBody())
                .isEqualTo(HttpStatus.OK);
        String accessToken = (String) tokenResponse.getBody().get("access_token");
        return SignedJWT.parse(accessToken).getJWTClaimsSet().getSubject();
    }

    private RSAKey fetchSigningKey() throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        ResponseEntity<String> jwks = restTemplate.exchange(
            baseUrl + "/.well-known/jwks.json",
            HttpMethod.GET,
            new HttpEntity<>(headers),
            String.class
        );
        JWKSet set = JWKSet.parse(jwks.getBody());
        return set.getKeys().get(0).toRSAKey();
    }

    private static Map<String, String> parseQuery(URI uri) {
        Map<String, String> result = new java.util.LinkedHashMap<>();
        String query = uri.getRawQuery();
        if (query == null) return result;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            String key = eq < 0 ? pair : pair.substring(0, eq);
            String value = eq < 0 ? "" : java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            result.put(key, value);
        }
        return result;
    }

    private static String randomVerifier() {
        byte[] bytes = new byte[48];
        new java.security.SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String s256(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
