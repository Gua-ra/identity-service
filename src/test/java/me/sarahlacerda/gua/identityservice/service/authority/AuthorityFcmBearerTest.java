// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import com.nimbusds.jwt.SignedJWT;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthorityFcmBearerTest {

    private static final Instant T0 = Instant.parse("2026-09-23T10:00:00Z");

    private IdentityServiceProperties properties;
    private CountingExchange exchange;
    private MutableClock clock;
    private AuthorityFcmBearer bearer;

    @BeforeEach
    void setUp() throws Exception {
        properties = new IdentityServiceProperties();
        IdentityServiceProperties.FcmProperties fcm = properties.getAuthority().getNotifications().getFcm();
        fcm.setBaseUrl("https://fcm.example.invalid");
        fcm.setProjectId("gua-test");
        fcm.setClientEmail("pusher@gua-test.iam.gserviceaccount.example");
        fcm.setPrivateKeyPkcs8Base64(generatedRsaKey());
        fcm.setTokenUri("https://oauth2.example.invalid/token");
        fcm.setRefreshSkew(Duration.ofMinutes(5));

        exchange = new CountingExchange();
        clock = new MutableClock(T0);
        bearer = new AuthorityFcmBearer(properties, exchange, clock);
    }

    @Test
    void theBearerIsMintedOnceAndReusedInsideItsLife() {
        assertThat(bearer.current()).isEqualTo("token-1");
        assertThat(bearer.current()).isEqualTo("token-1");

        clock.advance(Duration.ofMinutes(54));
        assertThat(bearer.current()).isEqualTo("token-1");
        assertThat(exchange.calls).hasSize(1);
    }

    @Test
    void theBearerIsExchangedAgainOnceTheSkewIsReached() {
        assertThat(bearer.current()).isEqualTo("token-1");

        clock.advance(Duration.ofMinutes(55));

        assertThat(bearer.current()).isEqualTo("token-2");
        assertThat(exchange.calls).hasSize(2);
    }

    @Test
    void theAssertionNamesTheServiceAccountTheTokenEndpointAndTheSendScope() throws Exception {
        bearer.current();

        String body = exchange.calls.getFirst();
        assertThat(body).startsWith("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=");
        SignedJWT jwt = SignedJWT.parse(java.net.URLDecoder.decode(
                body.substring(body.indexOf("&assertion=") + "&assertion=".length()),
                java.nio.charset.StandardCharsets.UTF_8));

        assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo("pusher@gua-test.iam.gserviceaccount.example");
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("pusher@gua-test.iam.gserviceaccount.example");
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("https://oauth2.example.invalid/token");
        assertThat(jwt.getJWTClaimsSet().getStringClaim("scope")).isEqualTo(AuthorityFcmBearer.SCOPE);
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
    }

    @Test
    void anExchangeThatReturnsNoUsableBearerIsAnError() {
        exchange.response = "{\"error\":\"invalid_grant\"}";

        assertThatThrownBy(() -> bearer.current())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no usable bearer");
    }

    private static String generatedRsaKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return Base64.getEncoder().encodeToString(generator.generateKeyPair().getPrivate().getEncoded());
    }

    private static final class CountingExchange implements AuthorityFcmBearer.Exchange {

        private final List<String> calls = new ArrayList<>();
        private String response;

        @Override
        public String post(String uri, String formBody) {
            calls.add(formBody);
            if (response != null) {
                return response;
            }
            return "{\"access_token\":\"token-" + calls.size() + "\",\"expires_in\":3600}";
        }
    }

    private static final class MutableClock extends Clock {

        private Instant now;

        private MutableClock(Instant now) {
            this.now = now;
        }

        private void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
