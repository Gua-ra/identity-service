// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.ApnsProperties;
import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration.Platform;

/**
 * Uses the JDK HttpClient because APNs requires HTTP/2. Sent as an alert so it is shown while the app is
 * signed out.
 */
@Component
public class AuthorityApnsTransport implements AuthorityPushTransport {

    private static final Logger log = LoggerFactory.getLogger(AuthorityApnsTransport.class);

    private final IdentityServiceProperties properties;
    private final HttpClient http;
    private final Clock clock;

    private String cachedToken;
    private Instant cachedUntil;

    @Autowired
    public AuthorityApnsTransport(IdentityServiceProperties properties, Clock clock) {
        this(properties, HttpClient.newBuilder().version(HttpClient.Version.HTTP_2).build(), clock);
    }

    AuthorityApnsTransport(IdentityServiceProperties properties, HttpClient http, Clock clock) {
        this.properties = properties;
        this.http = http;
        this.clock = clock;
    }

    @Override
    public Platform platform() {
        return Platform.APNS;
    }

    @Override
    public boolean isConfigured() {
        ApnsProperties apns = apns();
        return StringUtils.hasText(apns.getBaseUrl()) && StringUtils.hasText(apns.getKeyId())
                && StringUtils.hasText(apns.getTeamId())
                && StringUtils.hasText(apns.getPrivateKeyPkcs8Base64());
    }

    @Override
    public Outcome send(String token, String appId, String title, String body) {
        ApnsProperties apns = apns();
        String topic = apns.getTopics().getOrDefault(appId, appId);
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(apns.getBaseUrl() + "/3/device/" + token))
                    .header("authorization", "bearer " + providerToken())
                    .header("apns-topic", topic)
                    .header("apns-push-type", "alert")
                    .header("apns-priority", "10")
                    .header("content-type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(payload(title, body), StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            return outcome(response.statusCode(), response.body());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return Outcome.RETRYABLE;
        } catch (Exception ex) {
            log.warn("An authority alert could not be delivered to APNs: {}", ex.getMessage());
            return Outcome.RETRYABLE;
        }
    }

    private static Outcome outcome(int status, String body) {
        if (status >= 200 && status < 300) {
            return Outcome.DELIVERED;
        }
        if (status == 410 || (status == 400 && body != null && body.contains("BadDeviceToken"))) {
            return Outcome.UNREGISTERED;
        }
        log.warn("APNs refused an authority alert with status {}", status);
        return Outcome.RETRYABLE;
    }

    /** Must not carry a phone number or an account identifier. */
    private static String payload(String title, String body) {
        return "{\"aps\":{\"alert\":{\"title\":" + json(title) + ",\"body\":" + json(body)
                + "},\"sound\":\"default\",\"interruption-level\":\"time-sensitive\"},\""
                + AuthorityPushTransport.ALERT_MARKER + "\":\"1\"}";
    }

    private static String json(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append('"').toString();
    }

    synchronized String providerToken() {
        Instant now = clock.instant();
        if (cachedToken != null && cachedUntil != null && now.isBefore(cachedUntil)) {
            return cachedToken;
        }
        ApnsProperties apns = apns();
        try {
            ECPrivateKey key = (ECPrivateKey) AuthorityPushKeys.load("EC", apns.getPrivateKeyPkcs8Base64());
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .keyID(apns.getKeyId())
                            .type(JOSEObjectType.JWT)
                            .build(),
                    new JWTClaimsSet.Builder()
                            .issuer(apns.getTeamId())
                            .issueTime(Date.from(now))
                            .build());
            jwt.sign(new ECDSASigner(key));
            cachedToken = jwt.serialize();
            cachedUntil = now.plus(apns.getTokenLife());
            return cachedToken;
        } catch (Exception ex) {
            throw new IllegalStateException("the APNs provider token could not be signed", ex);
        }
    }

    private ApnsProperties apns() {
        return properties.getAuthority().getNotifications().getApns();
    }
}
