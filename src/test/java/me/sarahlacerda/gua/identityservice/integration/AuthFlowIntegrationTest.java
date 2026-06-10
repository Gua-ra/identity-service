package me.sarahlacerda.gua.identityservice.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSObject;
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
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriComponentsBuilder;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class AuthFlowIntegrationTest {

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
    }

    @LocalServerPort
    int port;

    @Autowired
    StringRedisTemplate redisTemplate;

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
    }

    @Test
    void fullPkceAuthorizationCodeFlowIssuesRs256AccessTokenAndReturnsUserInfo() throws Exception {
        String phone = "+15551112233";

        // 1. Send OTP
        sendOtp(phone);
        String otp = readOtpFromRedis(phone);
        assertThat(otp).isNotBlank();

        // 2. Authorize with PKCE
        String verifier = randomVerifier();
        String challenge = s256(verifier);
        String state = UUID.randomUUID().toString();
        URI authorizeUri = authorizeUrl(phone, otp, challenge, state);
        ResponseEntity<String> authorizeResponse = restTemplate.exchange(
            authorizeUri,
            HttpMethod.GET,
            HttpEntity.EMPTY,
            String.class
        );
        assertThat(authorizeResponse.getStatusCode())
            .as("authorize response body: %s", authorizeResponse.getBody())
            .isEqualTo(HttpStatus.FOUND);
        URI location = authorizeResponse.getHeaders().getLocation();
        assertThat(location).isNotNull();
        Map<String, String> query = parseQuery(location);
        assertThat(query.get("state")).isEqualTo(state);
        String code = query.get("code");
        assertThat(code).isNotBlank();

        // 3. Exchange code for tokens with verifier
        ResponseEntity<Map> tokenResponse = exchangeCode(code, verifier);
        assertThat(tokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        Map<?, ?> body = tokenResponse.getBody();
        assertThat(body).isNotNull();
        String accessToken = (String) body.get("access_token");
        String idToken = (String) body.get("id_token");
        assertThat(accessToken).isNotBlank();
        assertThat(idToken).isNotBlank();
        assertThat(body.get("token_type")).isEqualTo("Bearer");

        // 4. Validate access token signature with public JWKS
        SignedJWT signedAccess = SignedJWT.parse(accessToken);
        assertThat(signedAccess.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        RSAKey publicKey = fetchSigningKey();
        assertThat(signedAccess.verify(new RSASSAVerifier(publicKey.toRSAPublicKey()))).isTrue();
        JWTClaimsSet claims = signedAccess.getJWTClaimsSet();
        assertThat(claims.getSubject()).isNotBlank();
        assertThat(claims.getAudience()).contains("gua-ios");

        // 5. Call /userinfo
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
    }

    @Test
    void replayingAuthorizationCodeIsRejected() throws Exception {
        String phone = "+15552223344";

        sendOtp(phone);
        String otp = readOtpFromRedis(phone);
        String verifier = randomVerifier();
        String challenge = s256(verifier);

        ResponseEntity<Void> authorize = restTemplate.exchange(
            authorizeUrl(phone, otp, challenge, "state-x"),
            HttpMethod.GET,
            HttpEntity.EMPTY,
            Void.class
        );
        String code = parseQuery(authorize.getHeaders().getLocation()).get("code");

        ResponseEntity<Map> first = exchangeCode(code, verifier);
        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.OK);

        ResponseEntity<Map> second = exchangeCode(code, verifier);
        assertThat(second.getStatusCode()).isEqualTo(BAD_REQUEST);
        assertThat(second.getBody()).containsEntry("code", "invalid_grant");
    }

    @Test
    void mismatchedPkceVerifierIsRejected() throws Exception {
        String phone = "+15553334455";

        sendOtp(phone);
        String otp = readOtpFromRedis(phone);
        String verifier = randomVerifier();
        String wrongVerifier = randomVerifier();
        String challenge = s256(verifier);

        ResponseEntity<Void> authorize = restTemplate.exchange(
            authorizeUrl(phone, otp, challenge, "state-y"),
            HttpMethod.GET,
            HttpEntity.EMPTY,
            Void.class
        );
        String code = parseQuery(authorize.getHeaders().getLocation()).get("code");

        ResponseEntity<Map> response = exchangeCode(code, wrongVerifier);
        assertThat(response.getStatusCode()).isEqualTo(BAD_REQUEST);
        assertThat(response.getBody()).containsEntry("code", "invalid_grant");
    }

    @Test
    void publicClientRejectedWhenPkceMissing() throws Exception {
        String phone = "+15554445566";

        sendOtp(phone);
        String otp = readOtpFromRedis(phone);

        StringBuilder sb = new StringBuilder(baseUrl).append("/oauth2/authorize?");
        appendParam(sb, "response_type", "code");
        appendParam(sb, "client_id", "gua-ios");
        appendParam(sb, "redirect_uri", "me.sarahlacerda.gua://oidc");
        appendParam(sb, "scope", "openid profile");
        appendParam(sb, "phone_number", phone);
        appendParam(sb, "otp_code", otp);
        sb.setLength(sb.length() - 1);
        URI url = URI.create(sb.toString());
        ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, HttpEntity.EMPTY, Map.class);
        assertThat(response.getStatusCode()).isEqualTo(BAD_REQUEST);
        assertThat(response.getBody()).containsEntry("code", "invalid_request");
    }

    @Test
    void unknownClientIdReturnsInvalidClient() throws Exception {
        String phone = "+15555556677";
        sendOtp(phone);
        String otp = readOtpFromRedis(phone);

        StringBuilder sb = new StringBuilder(baseUrl).append("/oauth2/authorize?");
        appendParam(sb, "response_type", "code");
        appendParam(sb, "client_id", "no-such-client");
        appendParam(sb, "redirect_uri", "me.sarahlacerda.gua://oidc");
        appendParam(sb, "scope", "openid");
        appendParam(sb, "phone_number", phone);
        appendParam(sb, "otp_code", otp);
        sb.setLength(sb.length() - 1);
        URI url = URI.create(sb.toString());
        ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, HttpEntity.EMPTY, Map.class);
        assertThat(response.getStatusCode()).isEqualTo(BAD_REQUEST);
        assertThat(response.getBody()).containsEntry("code", "invalid_client");
    }

    private void sendOtp(String phone) {
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

    private URI authorizeUrl(String phone, String otp, String challenge, String state) {
        StringBuilder sb = new StringBuilder(baseUrl).append("/oauth2/authorize?");
        appendParam(sb, "response_type", "code");
        appendParam(sb, "client_id", "gua-ios");
        appendParam(sb, "redirect_uri", "me.sarahlacerda.gua://oidc");
        appendParam(sb, "scope", "openid profile phone");
        appendParam(sb, "phone_number", phone);
        appendParam(sb, "otp_code", otp);
        appendParam(sb, "state", state);
        appendParam(sb, "code_challenge", challenge);
        appendParam(sb, "code_challenge_method", "S256");
        // strip trailing &
        sb.setLength(sb.length() - 1);
        return URI.create(sb.toString());
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
        form.add("redirect_uri", "me.sarahlacerda.gua://oidc");
        form.add("client_id", "gua-ios");
        form.add("code_verifier", verifier);
        return restTemplate.exchange(
            baseUrl + "/oauth2/token",
            HttpMethod.POST,
            new HttpEntity<>(form, headers),
            Map.class
        );
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
