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
import java.util.Set;
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

/** Codes come only from /oauth2/authorize and the /login/** steps. The OTP is read from Redis (otp:code:<E.164>). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class AuthFlowIntegrationTest {

    private static final String CLIENT_ID = "gua-ios";
    private static final String REDIRECT_URI = "global.gua:/oidc";
    private static final String LOGIN_UI = "/signin";
    private static final String LOGIN_COOKIE = "gua_login";
    private static final String CSRF_HEADER = "X-CSRF-Token";
    private static final Pattern LOGIN_COOKIE_VALUE = Pattern.compile(LOGIN_COOKIE + "=([^;]+)");
    private static final String NEW_ACCOUNT_PIN = "739164";

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
        registry.add("identity.directory.pepper", () -> "test-pepper");
        registry.add("identity.sms.twilio.enabled", () -> "false");
        registry.add("identity.rate-limits.enabled", () -> "false");

        registry.add("oidc.issuer", () -> "http://localhost");
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

        wireMock.resetAll();
        wireMock.stubFor(get(urlPathMatching("/_synapse/admin/v1/threepid/msisdn/users/.*"))
                .willReturn(notFound()));
        wireMock.stubFor(get(urlPathMatching("/_synapse/admin/v2/users/.*"))
                .willReturn(notFound()));

        // All tests call from localhost and share the per-address OTP budget, so that counter is cleared
        // between methods.
        Set<String> requesterBudgets = redisTemplate.keys("otp:rate:ip:*");
        if (requesterBudgets != null && !requesterBudgets.isEmpty()) {
            redisTemplate.delete(requesterBudgets);
        }
    }

    @Test
    void fullPkceAuthorizationCodeFlowIssuesRs256AccessTokenAndReturnsUserInfo() throws Exception {
        String phone = "+16042250001";
        String verifier = randomVerifier();
        String challenge = s256(verifier);
        String state = UUID.randomUUID().toString();

        URI redirect = signInInteractively(phone, challenge, state, NEW_ACCOUNT_PIN, null);
        assertThat(redirect.toString()).startsWith(REDIRECT_URI);
        Map<String, String> query = parseQuery(redirect);
        assertThat(query.get("state")).isEqualTo(state);
        String code = query.get("code");
        assertThat(code).isNotBlank();

        ResponseEntity<Map> tokenResponse = exchangeCode(code, verifier);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> body = tokenResponse.getBody();
        assertThat(body).isNotNull();
        String accessToken = (String) body.get("access_token");
        String idToken = (String) body.get("id_token");
        assertThat(accessToken).isNotBlank();
        assertThat(idToken).isNotBlank();
        assertThat(body.get("token_type")).isEqualTo("Bearer");

        SignedJWT signedAccess = SignedJWT.parse(accessToken);
        assertThat(signedAccess.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        RSAKey publicKey = fetchSigningKey();
        assertThat(signedAccess.verify(new RSASSAVerifier(publicKey.toRSAPublicKey()))).isTrue();
        JWTClaimsSet claims = signedAccess.getJWTClaimsSet();
        assertThat(claims.getSubject()).isNotBlank();
        assertThat(claims.getAudience()).contains(CLIENT_ID);

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

        String code = parseQuery(signInInteractively(phone, challenge, "state-x", NEW_ACCOUNT_PIN, null)).get("code");

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

        String code = parseQuery(signInInteractively(phone, challenge, "state-y", NEW_ACCOUNT_PIN, null)).get("code");

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

    @Test
    void returningUserWithPinMustPresentItBeforeCodeIsIssued() throws Exception {
        String phone = "+16042250004";
        String pin = "482913";

        String firstVerifier = randomVerifier();
        String firstCode = parseQuery(signInInteractively(phone, s256(firstVerifier), "state-p1", pin, null))
                .get("code");
        String firstSubject = subjectOf(exchangeCode(firstCode, firstVerifier));

        String secondVerifier = randomVerifier();
        LoginClient login = startAuthorize(s256(secondVerifier), "state-p2");
        Map<?, ?> state = login.post("/login/phone", Map.of("phoneNumber", phone));
        assertThat(state.get("phase")).isEqualTo("OTP_SENT");
        state = login.post("/login/otp", Map.of("code", readOtpFromRedis(phone)));
        assertThat(state.get("phase")).isEqualTo("PIN_REQUIRED");
        assertThat(state.get("redirectUrl")).isNull();

        ResponseEntity<Map> skip = login.postRaw("/login/passkey/setup-skip", Map.of());
        assertThat(skip.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(skip.getBody()).containsEntry("code", "unexpected_step");

        ResponseEntity<Map> wrongPin = login.postRaw("/login/pin", Map.of("pin", "735182"));
        assertThat(wrongPin.getStatusCode()).isEqualTo(BAD_REQUEST);
        assertThat(wrongPin.getBody()).containsEntry("code", "invalid_pin");
        assertThat(login.get("/login/context").get("phase")).isEqualTo("PIN_REQUIRED");

        state = login.post("/login/pin", Map.of("pin", pin));
        URI redirect = login.driveToCode(state, null, null);
        Map<String, String> query = parseQuery(redirect);
        assertThat(query.get("state")).isEqualTo("state-p2");
        assertThat(subjectOf(exchangeCode(query.get("code"), secondVerifier))).isEqualTo(firstSubject);
    }

    @Test
    void aNewAccountCannotSkipThePinAndNoCodeIsIssued() throws Exception {
        String phone = "+16042250006";
        LoginClient login = startAuthorize(s256(randomVerifier()), "state-skip");
        login.post("/login/phone", Map.of("phoneNumber", phone));
        Map<?, ?> state = login.post("/login/otp", Map.of("code", readOtpFromRedis(phone)));
        assertThat(state.get("phase")).isEqualTo("PROFILE_REQUIRED");
        state = login.post("/login/profile", Map.of("username",
                "it" + UUID.randomUUID().toString().replace("-", "").substring(0, 10), "displayName", "Skip"));
        if ("PASSKEY_SETUP".equals(state.get("phase"))) {
            state = login.post("/login/passkey/setup-skip", Map.of());
        }
        assertThat(state.get("phase")).isEqualTo("PIN_SETUP");
        long codesBefore = authorizationCodeCount();

        for (Map<String, ?> body : List.<Map<String, ?>>of(Map.of("skip", true), Map.of(), Map.of("pin", "  "))) {
            ResponseEntity<Map> refused = login.postRaw("/login/pin-setup", body);
            assertThat(refused.getStatusCode()).isEqualTo(BAD_REQUEST);
            assertThat(refused.getBody()).containsEntry("code", "pin_required");
        }

        assertThat(login.get("/login/context").get("phase")).isEqualTo("PIN_SETUP");
        assertThat(authorizationCodeCount()).isEqualTo(codesBefore);
    }

    @Test
    void recoveryIsTooSoonRightAfterASignIn() throws Exception {
        String phone = "+16042250007";
        signInInteractively(phone, s256(randomVerifier()), "state-r1", NEW_ACCOUNT_PIN, null);

        LoginClient login = startAuthorize(s256(randomVerifier()), "state-r2");
        login.post("/login/phone", Map.of("phoneNumber", phone));
        Map<?, ?> state = login.post("/login/otp", Map.of("code", readOtpFromRedis(phone)));
        assertThat(state.get("phase")).isEqualTo("PIN_REQUIRED");
        Map<?, ?> recovery = (Map<?, ?>) state.get("recovery");
        assertThat(recovery).isNotNull();
        assertThat(recovery.get("status")).isEqualTo("TOO_SOON");
        assertThat(recovery.get("availableAtEpochSeconds")).isInstanceOf(Number.class);
        assertThat(((Number) recovery.get("availableAtEpochSeconds")).longValue() % 86400).isZero();

        String otpKey = "otp:code:" + phone;
        String codeBefore = redisTemplate.opsForValue().get(otpKey);
        ResponseEntity<Map> refused = login.postRaw("/login/recovery/start", Map.of());
        assertThat(refused.getStatusCode()).isEqualTo(BAD_REQUEST);
        assertThat(refused.getBody()).containsEntry("code", "recovery_cooldown_active");
        assertThat(refused.getHeaders().getFirst("Retry-After")).isNotBlank();
        assertThat(redisTemplate.opsForValue().get(otpKey)).isEqualTo(codeBefore);
    }

    @Test
    void anInteractiveSignupCanReauthenticateWithItsOwnNumber() throws Exception {
        String phone = "+16042250009";
        String strangersPhone = "+16042250010";
        String verifier = randomVerifier();
        URI redirect = signInInteractively(phone, s256(verifier), "state-reauth", NEW_ACCOUNT_PIN, null);
        String accessToken = (String) exchangeCode(parseQuery(redirect).get("code"), verifier).getBody()
                .get("access_token");
        assertThat(accessToken).isNotBlank();

        ResponseEntity<Map> refused = authenticatedPost(accessToken, "/account/reauth/start",
                Map.of("phone", strangersPhone));
        assertThat(refused.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(refused.getBody()).containsEntry("code", "reauth_phone_mismatch");
        assertThat(readOtpFromRedis(strangersPhone)).isNull();

        ResponseEntity<Map> started = authenticatedPost(accessToken, "/account/reauth/start",
                Map.of("phone", phone));
        assertThat(started.getStatusCode()).as("start: %s", started.getBody()).isEqualTo(HttpStatus.ACCEPTED);
        String otp = readOtpFromRedis(phone);
        assertThat(otp).isNotBlank();

        ResponseEntity<Map> verified = authenticatedPost(accessToken, "/account/reauth/verify",
                Map.of("phone", phone, "code", otp, "operation", "PHONE_CHANGE"));
        assertThat(verified.getStatusCode()).as("verify: %s", verified.getBody()).isEqualTo(HttpStatus.OK);
        assertThat((String) verified.getBody().get("reauthToken")).isNotBlank();

        ResponseEntity<Map> refusedVerify = authenticatedPost(accessToken, "/account/reauth/verify",
                Map.of("phone", strangersPhone, "code", "123456", "operation", "PHONE_CHANGE"));
        assertThat(refusedVerify.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(refusedVerify.getBody()).containsEntry("code", "reauth_phone_mismatch");
    }

    @Test
    void aBearerSessionIsSentToTheEnrollmentFlowToAddAFactor() throws Exception {
        String phone = "+16042250011";
        String verifier = randomVerifier();
        URI redirect = signInInteractively(phone, s256(verifier), "state-enroll", NEW_ACCOUNT_PIN, null);
        String accessToken = (String) exchangeCode(parseQuery(redirect).get("code"), verifier).getBody()
                .get("access_token");

        ResponseEntity<Map> refused = authenticatedPost(accessToken, "/security/pin",
                Map.of("userId", "@whoever:example.com", "newPin", "284917"));
        assertThat(refused.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(refused.getBody()).containsEntry("code", "step_up_required");

        ResponseEntity<Map> already = authenticatedPost(accessToken, "/security/pin/enroll/start", Map.of());
        assertThat(already.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(already.getBody()).containsEntry("code", "pin_already_set");

        ResponseEntity<Map> enroll = authenticatedPost(accessToken, "/security/passkey/enroll/start", Map.of());
        assertThat(enroll.getStatusCode()).as("enroll: %s", enroll.getBody()).isEqualTo(HttpStatus.OK);
        String enrollUrl = (String) enroll.getBody().get("enrollUrl");
        assertThat(enrollUrl).contains("/login/enroll/");

        ResponseEntity<String> opened = restTemplate.exchange(
                URI.create(baseUrl + enrollUrl.substring(enrollUrl.indexOf("/login/enroll/"))),
                HttpMethod.GET, HttpEntity.EMPTY, String.class);
        assertThat(opened.getStatusCode()).isEqualTo(HttpStatus.FOUND);

        LoginClient enrollSession = new LoginClient(loginCookie(opened.getHeaders()), null);
        Map<?, ?> context = enrollSession.get("/login/context");
        assertThat(context.get("phase")).isEqualTo("ENROLL_STEP_UP");
        assertThat(context.get("enrollment")).isEqualTo(true);
        assertThat(context.get("recovery")).isNull();

        LoginClient withCsrf = new LoginClient(enrollSession.cookie, (String) context.get("csrfToken"));
        ResponseEntity<Map> tooEarly = withCsrf.postRaw("/login/passkey/register/options", Map.of());
        assertThat(tooEarly.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(tooEarly.getBody()).containsEntry("code", "unexpected_step");
    }

    @Test
    void theRetiredPinResetEndpointsAnswerGoneWithoutABearerToken() {
        for (String path : List.of("/security/pin/reset", "/security/pin/reset/complete")) {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            ResponseEntity<Map> response = restTemplate.exchange(baseUrl + path, HttpMethod.POST,
                    new HttpEntity<>(Map.of("userId", "@x:example.com", "phone", "+16042250008"), headers), Map.class);
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.GONE);
            assertThat(response.getBody()).containsEntry("code", "endpoint_retired");
        }
    }

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

        String cookie = loginCookie(response.getHeaders());
        LoginClient login = new LoginClient(cookie, null);
        Map<?, ?> context = login.get("/login/context");
        assertThat(context.get("phase")).isEqualTo("PHONE");
        assertThat(context.get("maskedPhone")).isNull();
        assertThat(context.get("redirectUrl")).isNull();

        assertThat(readOtpFromRedis(phone)).isEqualTo(otp);
        assertThat(directoryService.findByDigest(phoneNumberHasher.digest(phone))).isEmpty();
        assertThat(authorizationCodeCount()).isEqualTo(codesBefore);
    }

    @Test
    void passkeyLoginHintParksPasskeyIntentAndOffersAssertionOptions() throws Exception {
        StringBuilder sb = new StringBuilder(baseUrl).append("/oauth2/authorize?");
        appendParam(sb, "response_type", "code");
        appendParam(sb, "client_id", CLIENT_ID);
        appendParam(sb, "redirect_uri", REDIRECT_URI);
        appendParam(sb, "scope", "openid profile phone");
        appendParam(sb, "state", "state-passkey");
        appendParam(sb, "login_hint", "passkey");
        appendParam(sb, "code_challenge", s256(randomVerifier()));
        appendParam(sb, "code_challenge_method", "S256");
        sb.setLength(sb.length() - 1);

        ResponseEntity<String> response = restTemplate.exchange(URI.create(sb.toString()), HttpMethod.GET,
                HttpEntity.EMPTY, String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        assertThat(response.getHeaders().getLocation()).hasToString(LOGIN_UI);

        LoginClient anonymous = new LoginClient(loginCookie(response.getHeaders()), null);
        Map<?, ?> context = anonymous.get("/login/context");
        assertThat(context.get("phase")).isEqualTo("PHONE");
        assertThat(context.get("intent")).isEqualTo("PASSKEY");
        assertThat(context.get("phoneHint")).isNull();
        assertThat(context.get("maskedPhone")).isNull();

        LoginClient login = new LoginClient(anonymous.cookie, (String) context.get("csrfToken"));
        Map<?, ?> options = login.post("/login/passkey/auth/options", Map.of());
        Map<?, ?> publicKey = (Map<?, ?>) options.get("publicKey");
        assertThat(publicKey).as("assertion options: %s", options).isNotNull();
        assertThat((String) publicKey.get("challenge")).isNotBlank();
    }

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
        assertThat(context.get("intent")).isEqualTo("PHONE");
        String csrf = (String) context.get("csrfToken");
        assertThat(csrf).isNotBlank();
        return new LoginClient(login.cookie, csrf);
    }

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

        URI driveToCode(Map<?, ?> current, String pinToSetUp, String existingPin) {
            for (int step = 0; step < 6; step++) {
                String phase = (String) current.get("phase");
                switch (phase) {
                    case "PROFILE_REQUIRED" -> current = post("/login/profile",
                            Map.of("username", "it" + UUID.randomUUID().toString().replace("-", "").substring(0, 10),
                                    "displayName", "Integration User"));
                    case "PIN_SETUP" -> {
                        assertThat(pinToSetUp).as("PIN setup cannot be skipped, so the flow needs a PIN").isNotNull();
                        current = post("/login/pin-setup", Map.of("pin", pinToSetUp));
                    }
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
            // RestTemplate prefers XML when jackson-dataformat-xml is on the classpath, so JSON is requested
            // explicitly.
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            headers.add(HttpHeaders.COOKIE, LOGIN_COOKIE + "=" + cookie);
            if (csrf != null) {
                headers.add(CSRF_HEADER, csrf);
            }
            return headers;
        }
    }

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

    private ResponseEntity<Map> authenticatedPost(String accessToken, String path, Map<String, ?> body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(accessToken);
        return restTemplate.exchange(baseUrl + path, HttpMethod.POST, new HttpEntity<>(body, headers), Map.class);
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
