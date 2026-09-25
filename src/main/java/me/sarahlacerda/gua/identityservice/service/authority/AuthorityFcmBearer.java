// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.FcmProperties;

/**
 * The FCM bearer, minted with the library this service already has.
 *
 * <p>The decision, taken rather than left open: no Google auth dependency. A service-account bearer is a
 * signed assertion exchanged at one endpoint, nimbus is already on this classpath for the OIDC work, and the
 * alternative is a new transitive tree plus a second credential-loading path for a single POST. The cost is
 * that the exchange is written here, in twenty lines a reader can check, which is the point.
 *
 * <p>Cached to its own expiry, less {@link FcmProperties#getRefreshSkew()}, so a send never races the
 * exchange. {@code AuthorityFcmBearerTest} advances a clock across that boundary and asserts the second call
 * exchanges again while calls inside the window do not, because a cache that never refreshes and a cache that
 * refreshes per send look identical until a token expires in production.
 */
@Component
public class AuthorityFcmBearer {

    /** What the assertion asks for, which is the send scope and nothing wider. */
    static final String SCOPE = "https://www.googleapis.com/auth/firebase.messaging";

    private static final ObjectMapper JSON = new ObjectMapper();

    private final IdentityServiceProperties properties;
    private final Exchange exchange;
    private final Clock clock;

    private String cached;
    private Instant cachedUntil;

    @Autowired
    public AuthorityFcmBearer(IdentityServiceProperties properties, Clock clock) {
        this(properties, new HttpExchange(HttpClient.newHttpClient()), clock);
    }

    AuthorityFcmBearer(IdentityServiceProperties properties, Exchange exchange, Clock clock) {
        this.properties = properties;
        this.exchange = exchange;
        this.clock = clock;
    }

    /**
     * A usable bearer, from the cache when one is still good.
     *
     * <p>Synchronized rather than lock-free: two sends racing the first exchange would otherwise mint two
     * assertions for no gain, and the contended path is one HTTPS round trip an hour.
     */
    public synchronized String current() {
        Instant now = clock.instant();
        if (cached != null && cachedUntil != null && now.isBefore(cachedUntil)) {
            return cached;
        }
        FcmProperties fcm = properties.getAuthority().getNotifications().getFcm();
        String body = "grant_type=" + URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer",
                StandardCharsets.UTF_8)
                + "&assertion=" + URLEncoder.encode(assertion(fcm, now), StandardCharsets.UTF_8);

        String response = exchange.post(fcm.getTokenUri(), body);
        try {
            JsonNode parsed = JSON.readTree(response);
            String token = parsed.path("access_token").asText(null);
            long expiresIn = parsed.path("expires_in").asLong(0L);
            if (token == null || expiresIn <= 0) {
                throw new IllegalStateException("the FCM token exchange returned no usable bearer");
            }
            cached = token;
            // Held to the expiry the exchange stated, less the skew, so the value is never used at its edge.
            Duration life = Duration.ofSeconds(expiresIn).minus(fcm.getRefreshSkew());
            cachedUntil = now.plus(life.isNegative() ? Duration.ofSeconds(expiresIn) : life);
            return cached;
        } catch (IllegalStateException ex) {
            throw ex;
        } catch (Exception ex) {
            // Never the response body: it carries the bearer on the success path.
            throw new IllegalStateException("the FCM token exchange could not be read", ex);
        }
    }

    private static String assertion(FcmProperties fcm, Instant now) {
        try {
            RSAPrivateKey key = (RSAPrivateKey) AuthorityPushKeys.load("RSA", fcm.getPrivateKeyPkcs8Base64());
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).build(),
                    new JWTClaimsSet.Builder()
                            .issuer(fcm.getClientEmail())
                            .subject(fcm.getClientEmail())
                            .audience(List.of(fcm.getTokenUri()))
                            .claim("scope", SCOPE)
                            .issueTime(Date.from(now))
                            .expirationTime(Date.from(now.plus(Duration.ofMinutes(60))))
                            .build());
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        } catch (Exception ex) {
            throw new IllegalStateException("the FCM assertion could not be signed", ex);
        }
    }

    /** The one round trip, behind a seam so a test can count exchanges without a network. */
    interface Exchange {
        String post(String uri, String formBody);
    }

    /** The shipped exchange. */
    static final class HttpExchange implements Exchange {

        private final HttpClient http;

        HttpExchange(HttpClient http) {
            this.http = http;
        }

        @Override
        public String post(String uri, String formBody) {
            HttpRequest request = HttpRequest.newBuilder(URI.create(uri))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(formBody, StandardCharsets.UTF_8))
                    .build();
            try {
                HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() < 200 || response.statusCode() >= 300) {
                    throw new IllegalStateException("the FCM token exchange answered " + response.statusCode());
                }
                return response.body();
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("the FCM token exchange was interrupted", ex);
            } catch (IllegalStateException ex) {
                throw ex;
            } catch (Exception ex) {
                throw new IllegalStateException("the FCM token exchange failed", ex);
            }
        }
    }
}
