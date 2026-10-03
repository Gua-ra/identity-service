package me.sarahlacerda.gua.identityservice.integration;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.notFound;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import me.sarahlacerda.gua.identityservice.controller.oidc.LoginFlowController;
import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.exception.InvalidOtpException;
import me.sarahlacerda.gua.identityservice.exception.OtpRateLimitedException;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import me.sarahlacerda.gua.identityservice.service.OtpScope;
import me.sarahlacerda.gua.identityservice.service.OtpService;
import me.sarahlacerda.gua.identityservice.service.PhoneNumberHasher;
import me.sarahlacerda.gua.identityservice.service.ReviewLogin;
import me.sarahlacerda.gua.identityservice.service.SmsSender;
import me.sarahlacerda.gua.identityservice.service.security.AccountReauthService;
import me.sarahlacerda.gua.identityservice.service.security.PhoneChangeOtpService;
import me.sarahlacerda.gua.identityservice.service.security.ReauthOperation;

/**
 * The store review login switched on, over real HTTP against Postgres and Redis: the review number
 * signs in with the review code and still needs its PIN, with no SMS; the code keeps every rule a
 * texted code has; and no other purpose or number is touched.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class ReviewLoginIntegrationTest {

    private static final String REVIEW_PHONE = "+16042259911";
    private static final String OTHER_PHONE = "+16042259912";
    private static final String REVIEW_CODE = "246802";
    private static final String REVIEW_CODE_HASH = new BCryptPasswordEncoder(10).encode(REVIEW_CODE);
    private static final String REVIEW_PIN = "739164";
    private static final String CLIENT_ID = "gua-ios";
    private static final String REDIRECT_URI = "global.gua:/oidc";
    private static final String LOGIN_COOKIE = "gua_login";
    private static final Pattern LOGIN_COOKIE_VALUE = Pattern.compile(LOGIN_COOKIE + "=([^;]+)");
    private static final String IP = "203.0.113.40";

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
        if (wireMock != null) {
            wireMock.stop();
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

        registry.add("identity.matrix.admin-api-base-url", () -> wireMock.baseUrl());
        registry.add("identity.matrix.client-api-base-url", () -> wireMock.baseUrl());
        registry.add("identity.matrix.homeserver-domain", () -> "example.com");
        registry.add("identity.matrix.admin-access-token", () -> "test-admin-token");
        registry.add("identity.directory.pepper", () -> "test-pepper");
        registry.add("identity.sms.twilio.enabled", () -> "false");
        registry.add("identity.rate-limits.enabled", () -> "false");
        registry.add("oidc.issuer", () -> "http://localhost");
        registry.add("idp.login.cookie-name", () -> LOGIN_COOKIE);
        registry.add("idp.login.registration.web-allowlist-enabled", () -> "false");

        registry.add("identity.review-login.enabled", () -> "true");
        registry.add("identity.review-login.phone", () -> REVIEW_PHONE);
        registry.add("identity.review-login.code-hash", () -> REVIEW_CODE_HASH);
    }

    @LocalServerPort
    int port;

    @MockitoSpyBean
    SmsSender smsSender;

    @Autowired
    StringRedisTemplate redisTemplate;
    @Autowired
    OtpService otpService;
    @Autowired
    AccountReauthService accountReauthService;
    @Autowired
    PhoneChangeOtpService phoneChangeOtpService;
    @Autowired
    DirectoryService directoryService;
    @Autowired
    PhoneNumberHasher phoneNumberHasher;
    @Autowired
    MeterRegistry metrics;

    private RestTemplate restTemplate;
    private String baseUrl;
    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private final List<Class<?>> loggedClasses = List.of(ReviewLogin.class, OtpService.class,
            LoginFlowController.class, AccountReauthService.class);

    @BeforeEach
    void setUp() {
        org.springframework.http.client.SimpleClientHttpRequestFactory factory = new org.springframework.http.client.SimpleClientHttpRequestFactory() {
            @Override
            protected void prepareConnection(java.net.HttpURLConnection connection, String httpMethod)
                    throws java.io.IOException {
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
        wireMock.stubFor(get(urlPathMatching("/_synapse/admin/v1/threepid/msisdn/users/.*")).willReturn(notFound()));
        wireMock.stubFor(get(urlPathMatching("/_synapse/admin/v2/users/.*")).willReturn(notFound()));

        // Each test starts with its own send budgets and no live code for the two numbers.
        deleteKeys("otp:rate:*");
        deleteKeys("reauth:phone-mismatch:*");
        for (String phone : List.of(REVIEW_PHONE, OTHER_PHONE)) {
            redisTemplate.delete(List.of("otp:code:" + phone, "otp:attempts:" + phone, "otp:review-login:" + phone));
        }

        logs.list.clear();
        logs.start();
        loggedClasses.forEach(type -> ((Logger) LoggerFactory.getLogger(type)).addAppender(logs));
    }

    @AfterEach
    void neitherTheCodeNorItsHashIsEverLogged() {
        loggedClasses.forEach(type -> ((Logger) LoggerFactory.getLogger(type)).detachAppender(logs));
        assertThat(logs.list).allSatisfy(event -> {
            assertThat(event.getFormattedMessage()).doesNotContain(REVIEW_CODE).doesNotContain(REVIEW_CODE_HASH);
            if (event.getThrowableProxy() != null) {
                assertThat(event.getThrowableProxy().getMessage()).doesNotContain(REVIEW_CODE);
            }
        });
        assertThat(logs.list).filteredOn(event -> event.getLoggerName().equals(ReviewLogin.class.getName()))
                .allSatisfy(event -> assertThat(event.getFormattedMessage()).doesNotContain(REVIEW_PHONE));
    }

    // -------------------- the review sign-in --------------------

    @Test
    void theReviewNumberSignsInWithTheReviewCodeAndStillNeedsItsPin() throws Exception {
        reviewAccountUserId();
        double sentBefore = review("sent");

        LoginClient login = startAuthorize();
        assertThat(login.post("/login/phone", Map.of("phoneNumber", REVIEW_PHONE)).get("phase")).isEqualTo("OTP_SENT");
        Map<?, ?> state = login.post("/login/otp", Map.of("code", REVIEW_CODE));

        // The code proves the number and nothing more: the account's PIN is still asked for.
        assertThat(state.get("phase")).isEqualTo("PIN_REQUIRED");
        assertThat(state.get("redirectUrl")).isNull();
        ResponseEntity<Map> wrongPin = login.postRaw("/login/pin", Map.of("pin", "735182"));
        assertThat(wrongPin.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(wrongPin.getBody()).containsEntry("code", "invalid_pin");

        state = login.post("/login/pin", Map.of("pin", REVIEW_PIN));
        if ("PASSKEY_SETUP".equals(state.get("phase"))) {
            state = login.post("/login/passkey/setup-skip", Map.of());
        }
        assertThat(state.get("phase")).isEqualTo("COMPLETED");
        assertThat((String) state.get("redirectUrl")).startsWith(REDIRECT_URI).contains("code=");

        verify(smsSender, never()).send(eq(REVIEW_PHONE), anyString());
        assertThat(review("sent")).isEqualTo(sentBefore + 1);
        assertThat(review("accepted")).isPositive();
        assertThat(logs.list).anySatisfy(event -> assertThat(event.getFormattedMessage())
                .isEqualTo("Store review login sent for ••••9911"));
    }

    /**
     * The review code is printed in the store's review instructions, so it must not open the
     * delayed recovery, which would let whoever holds it set a new PIN after the waits. Any other
     * number at the same step is still offered it.
     */
    @Test
    void theReviewCodeNeverOpensAccountRecovery() {
        reviewAccountUserId();

        LoginClient review = startAuthorize();
        review.post("/login/phone", Map.of("phoneNumber", REVIEW_PHONE));
        Map<?, ?> state = review.post("/login/otp", Map.of("code", REVIEW_CODE));
        assertThat(state.get("phase")).isEqualTo("PIN_REQUIRED");
        assertThat(state.containsKey("recovery")).isTrue();
        assertThat(state.get("recovery")).isNull();
        ResponseEntity<Map> start = review.postRaw("/login/recovery/start", Map.of());
        assertThat(start.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(start.getBody()).containsEntry("code", "recovery_unavailable");
        ResponseEntity<Map> complete = review.postRaw("/login/recovery/complete", Map.of("newPin", "284917"));
        assertThat(complete.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(complete.getBody()).containsEntry("code", "recovery_unavailable");
        // The PIN is still the way in, and still works.
        state = review.post("/login/pin", Map.of("pin", REVIEW_PIN));
        if ("PASSKEY_SETUP".equals(state.get("phase"))) {
            state = review.post("/login/passkey/setup-skip", Map.of());
        }
        assertThat(state.get("phase")).isEqualTo("COMPLETED");

        signUpOtherNumber();
        LoginClient other = startAuthorize();
        other.post("/login/phone", Map.of("phoneNumber", OTHER_PHONE));
        state = other.post("/login/otp", Map.of("code", textedCode(OTHER_PHONE)));
        assertThat(state.get("phase")).isEqualTo("PIN_REQUIRED");
        assertThat(state.get("recovery")).isNotNull();
    }

    @Test
    void theReviewSendAnswersLikeAnyOtherSend() {
        Map<?, ?> other = startAuthorize().post("/login/phone", Map.of("phoneNumber", OTHER_PHONE));
        Map<?, ?> reviewed = startAuthorize().post("/login/phone", Map.of("phoneNumber", REVIEW_PHONE));

        assertThat(reviewed.keySet()).isEqualTo(other.keySet());
        assertThat(reviewed.get("phase")).isEqualTo(other.get("phase"));
        assertThat(reviewed.get("maskedPhone")).isEqualTo("••••9911");
        // Both left a live code with the same lifetime and a fresh budget.
        assertThat(redisTemplate.getExpire("otp:code:" + REVIEW_PHONE))
                .isCloseTo(redisTemplate.getExpire("otp:code:" + OTHER_PHONE), org.assertj.core.data.Offset.offset(2L));
        assertThat(redisTemplate.hasKey("otp:attempts:" + REVIEW_PHONE)).isFalse();

        verify(smsSender).send(eq(OTHER_PHONE), anyString());
        verify(smsSender, never()).send(eq(REVIEW_PHONE), anyString());
    }

    // -------------------- the code keeps every rule a texted code has --------------------

    @Test
    void theReviewCodeIsAcceptedOnlyAfterASignInSendAndWithinItsValidity() throws Exception {
        // Never sent.
        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE))
                .isInstanceOf(InvalidOtpException.class);

        // Sent, then expired.
        otpService.sendLoginOtp(REVIEW_PHONE, IP, null);
        redisTemplate.expire("otp:code:" + REVIEW_PHONE, Duration.ofMillis(1));
        waitUntilGone("otp:code:" + REVIEW_PHONE);
        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE))
                .isInstanceOf(InvalidOtpException.class);

        // Sent, then replaced by a code another flow texted (what reauthentication and POST
        // /otp/send do): the review code no longer redeems it, the texted one does.
        otpService.sendLoginOtp(REVIEW_PHONE, IP, null);
        otpService.sendOtp(REVIEW_PHONE, IP, null);
        verify(smsSender).send(eq(REVIEW_PHONE), anyString());
        String texted = redisTemplate.opsForValue().get("otp:code:" + REVIEW_PHONE);
        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE))
                .isInstanceOf(InvalidOtpException.class);
        otpService.verifyLoginOtp(REVIEW_PHONE, texted);

        // Sent: accepted once, and only once.
        otpService.sendLoginOtp(REVIEW_PHONE, IP, null);
        otpService.verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE);
        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE))
                .isInstanceOf(InvalidOtpException.class);
    }

    @Test
    void fiveWrongCodesLockTheReviewCodeLikeAnyCode() {
        otpService.sendLoginOtp(REVIEW_PHONE, IP, null);
        int max = 5;
        for (int guess = 1; guess < max; guess++) {
            assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, "000000"))
                    .hasMessage("Invalid or expired verification code");
        }
        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, "000000"))
                .hasMessage("Too many incorrect verification codes; request a new code");
        assertThatThrownBy(() -> otpService.verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE))
                .isInstanceOf(InvalidOtpException.class);

        // Only a new send restores it.
        otpService.sendLoginOtp(REVIEW_PHONE, IP, null);
        otpService.verifyLoginOtp(REVIEW_PHONE, REVIEW_CODE);
    }

    @Test
    void theReviewSendSpendsTheSameRateBudgetAsAnyOtherSend() {
        for (int send = 1; send <= 5; send++) {
            otpService.sendLoginOtp(REVIEW_PHONE, IP, null);
        }
        assertThatThrownBy(() -> otpService.sendLoginOtp(REVIEW_PHONE, IP, null))
                .isInstanceOf(OtpRateLimitedException.class);
        // One budget for the number, whoever is sending.
        assertThatThrownBy(() -> otpService.sendOtp(REVIEW_PHONE, IP, null))
                .isInstanceOf(OtpRateLimitedException.class);
        verify(smsSender, never()).send(eq(REVIEW_PHONE), anyString());
        assertThat(review("send_rate_limited")).isPositive();
    }

    // -------------------- nothing else changes --------------------

    @Test
    void noOtherPurposeTakesTheReviewCodeAndEachStillTextsTheNumber() throws Exception {
        String userId = reviewAccountUserId();
        deleteKeys("otp:rate:*");

        // A change of number, old number: the reauthentication.
        accountReauthService.startReauth(userId, REVIEW_PHONE, IP, "en");
        assertThatThrownBy(() -> accountReauthService.verifyReauth(userId, REVIEW_PHONE, REVIEW_CODE,
                ReauthOperation.PHONE_CHANGE, IP)).isInstanceOf(InvalidOtpException.class);
        // Not even straight after a review sign-in send, or for the enrollment step-up.
        otpService.sendLoginOtp(REVIEW_PHONE, IP, null);
        assertThatThrownBy(() -> accountReauthService.verifyReauth(userId, REVIEW_PHONE, REVIEW_CODE,
                ReauthOperation.PHONE_CHANGE, IP)).isInstanceOf(InvalidOtpException.class);
        assertThatThrownBy(() -> accountReauthService.verifyPhoneOtp(userId, REVIEW_PHONE, REVIEW_CODE,
                "ENROLL_STEP_UP", IP)).isInstanceOf(InvalidOtpException.class);

        // A change of number, new number.
        phoneChangeOtpService.send("chal-review", REVIEW_PHONE, IP, "en");
        assertThatThrownBy(() -> phoneChangeOtpService.verify("chal-review", REVIEW_CODE))
                .isInstanceOf(InvalidOtpException.class);

        deleteKeys("otp:rate:*");
        // The PIN change.
        otpService.sendScopedOtp(OtpScope.PIN_CHANGE, "pin-review", REVIEW_PHONE, IP, null);
        assertThatThrownBy(() -> otpService.verifyScopedOtp(OtpScope.PIN_CHANGE, "pin-review", REVIEW_CODE))
                .isInstanceOf(InvalidOtpException.class);

        // The REST sign-in, which the web gate also guards.
        ResponseEntity<Void> sent = restPost("/otp/send", Map.of("phone", REVIEW_PHONE), Void.class);
        assertThat(sent.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        ResponseEntity<Map> refused = restPost("/otp/verify", Map.of("phone", REVIEW_PHONE, "code", REVIEW_CODE),
                Map.class);
        assertThat(refused.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(refused.getBody()).containsEntry("code", "invalid_otp");

        // Every one of them texted the number, as before.
        verify(smsSender, times(4)).send(eq(REVIEW_PHONE), anyString());
    }

    @Test
    void anyOtherNumberIsTextedAndTheReviewCodeMeansNothingForIt() {
        otpService.sendLoginOtp(OTHER_PHONE, IP, null);

        verify(smsSender).send(eq(OTHER_PHONE), anyString());
        assertThat(redisTemplate.hasKey("otp:review-login:" + OTHER_PHONE)).isFalse();
        String texted = redisTemplate.opsForValue().get("otp:code:" + OTHER_PHONE);
        if (!REVIEW_CODE.equals(texted)) {
            assertThatThrownBy(() -> otpService.verifyLoginOtp(OTHER_PHONE, REVIEW_CODE))
                    .isInstanceOf(InvalidOtpException.class);
        }
        otpService.verifyLoginOtp(OTHER_PHONE, texted);
    }

    // -------------------- helpers --------------------

    /**
     * The review account, created the way an operator would: by signing up the review number
     * through the interactive flow with the review code.
     */
    private String reviewAccountUserId() {
        String digest = phoneNumberHasher.digest(REVIEW_PHONE);
        return directoryService.findByDigest(digest).map(DirectoryEntry::getUserId).orElseGet(() -> {
            LoginClient login = startAuthorize();
            login.post("/login/phone", Map.of("phoneNumber", REVIEW_PHONE));
            Map<?, ?> state = login.post("/login/otp", Map.of("code", REVIEW_CODE));
            assertThat(state.get("phase")).isEqualTo("PROFILE_REQUIRED");
            state = login.post("/login/profile", Map.of("username",
                    "review" + UUID.randomUUID().toString().replace("-", "").substring(0, 8), "displayName", "Review"));
            if ("PASSKEY_SETUP".equals(state.get("phase"))) {
                state = login.post("/login/passkey/setup-skip", Map.of());
            }
            assertThat(state.get("phase")).isEqualTo("PIN_SETUP");
            state = login.post("/login/pin-setup", Map.of("pin", REVIEW_PIN));
            assertThat(state.get("phase")).isEqualTo("COMPLETED");
            deleteKeys("otp:rate:*");
            return directoryService.findByDigest(digest).orElseThrow().getUserId();
        });
    }

    /** An ordinary account on the other number, signed up with the code it was texted. */
    private void signUpOtherNumber() {
        if (directoryService.findByDigest(phoneNumberHasher.digest(OTHER_PHONE)).isPresent()) {
            return;
        }
        LoginClient login = startAuthorize();
        login.post("/login/phone", Map.of("phoneNumber", OTHER_PHONE));
        Map<?, ?> state = login.post("/login/otp", Map.of("code", textedCode(OTHER_PHONE)));
        assertThat(state.get("phase")).isEqualTo("PROFILE_REQUIRED");
        state = login.post("/login/profile", Map.of("username",
                "other" + UUID.randomUUID().toString().replace("-", "").substring(0, 8), "displayName", "Other"));
        if ("PASSKEY_SETUP".equals(state.get("phase"))) {
            state = login.post("/login/passkey/setup-skip", Map.of());
        }
        assertThat(state.get("phase")).isEqualTo("PIN_SETUP");
        state = login.post("/login/pin-setup", Map.of("pin", "518306"));
        assertThat(state.get("phase")).isEqualTo("COMPLETED");
        deleteKeys("otp:rate:*");
    }

    /** The live code the dev SMS sender would have texted to {@code phone}. */
    private String textedCode(String phone) {
        String code = redisTemplate.opsForValue().get("otp:code:" + phone);
        assertThat(code).isNotNull();
        return code;
    }

    private LoginClient startAuthorize() {
        byte[] verifier = new byte[48];
        new java.security.SecureRandom().nextBytes(verifier);
        String challenge;
        try {
            challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256")
                    .digest(Base64.getUrlEncoder().withoutPadding().encodeToString(verifier)
                            .getBytes(StandardCharsets.US_ASCII)));
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
        String url = baseUrl + "/oauth2/authorize?response_type=code&client_id=" + CLIENT_ID
                + "&redirect_uri=" + java.net.URLEncoder.encode(REDIRECT_URI, StandardCharsets.UTF_8)
                + "&scope=openid%20profile%20phone&state=s&code_challenge=" + challenge
                + "&code_challenge_method=S256";
        ResponseEntity<String> response = restTemplate.exchange(URI.create(url), HttpMethod.GET, HttpEntity.EMPTY,
                String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
        String cookie = null;
        for (String header : response.getHeaders().get(HttpHeaders.SET_COOKIE)) {
            Matcher matcher = LOGIN_COOKIE_VALUE.matcher(header);
            if (matcher.find()) {
                cookie = matcher.group(1);
            }
        }
        assertThat(cookie).isNotNull();
        LoginClient anonymous = new LoginClient(cookie, null);
        return new LoginClient(cookie, (String) anonymous.get("/login/context").get("csrfToken"));
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

        private HttpHeaders headers() {
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            headers.add(HttpHeaders.COOKIE, LOGIN_COOKIE + "=" + cookie);
            if (csrf != null) {
                headers.add("X-CSRF-Token", csrf);
            }
            return headers;
        }
    }

    private <T> ResponseEntity<T> restPost(String path, Map<String, ?> body, Class<T> type) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_JSON);
        return restTemplate.exchange(baseUrl + path, HttpMethod.POST, new HttpEntity<>(body, headers), type);
    }

    private void deleteKeys(String pattern) {
        Set<String> keys = redisTemplate.keys(pattern);
        if (keys != null && !keys.isEmpty()) {
            redisTemplate.delete(keys);
        }
    }

    private void waitUntilGone(String key) throws InterruptedException {
        for (int i = 0; i < 100 && Boolean.TRUE.equals(redisTemplate.hasKey(key)); i++) {
            Thread.sleep(10);
        }
        assertThat(redisTemplate.hasKey(key)).isFalse();
    }

    private double review(String outcome) {
        Counter counter = metrics.find("gua.identity.review.login").tag("outcome", outcome).counter();
        return counter == null ? 0.0 : counter.count();
    }
}
