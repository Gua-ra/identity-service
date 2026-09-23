// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.FcmProperties;
import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration.Platform;

/**
 * Firebase Cloud Messaging v1, spoken directly, with the bearer from {@link AuthorityFcmBearer}.
 *
 * <p>The message is sent as a notification rather than as data, for the same reason the APNs alert is an
 * alert: the case this channel exists for is an account whose sessions a recovery has just ended, so the app
 * may not be running and nothing may be there to handle a data message.
 */
@Component
public class AuthorityFcmTransport implements AuthorityPushTransport {

    private static final Logger log = LoggerFactory.getLogger(AuthorityFcmTransport.class);

    private final IdentityServiceProperties properties;
    private final AuthorityFcmBearer bearer;
    private final HttpClient http;

    @Autowired
    public AuthorityFcmTransport(IdentityServiceProperties properties, AuthorityFcmBearer bearer) {
        this(properties, bearer, HttpClient.newHttpClient());
    }

    AuthorityFcmTransport(IdentityServiceProperties properties, AuthorityFcmBearer bearer, HttpClient http) {
        this.properties = properties;
        this.bearer = bearer;
        this.http = http;
    }

    @Override
    public Platform platform() {
        return Platform.FCM;
    }

    @Override
    public boolean isConfigured() {
        FcmProperties fcm = fcm();
        return StringUtils.hasText(fcm.getBaseUrl()) && StringUtils.hasText(fcm.getProjectId())
                && StringUtils.hasText(fcm.getClientEmail())
                && StringUtils.hasText(fcm.getPrivateKeyPkcs8Base64());
    }

    @Override
    public Outcome send(String token, String appId, String title, String body) {
        FcmProperties fcm = fcm();
        String url = fcm.getBaseUrl() + "/v1/projects/" + fcm.getProjectId() + "/messages:send";
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .header("authorization", "Bearer " + bearer.current())
                .header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload(token, title, body), StandardCharsets.UTF_8))
                .build();
        try {
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            return outcome(response.statusCode(), response.body());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            return Outcome.RETRYABLE;
        } catch (Exception ex) {
            log.warn("An authority alert could not be delivered to FCM: {}", ex.getMessage());
            return Outcome.RETRYABLE;
        }
    }

    /**
     * FCM v1 reports a dead destination as 404 {@code UNREGISTERED}, and a token that never belonged as 400
     * {@code INVALID_ARGUMENT}. Only the first retires a row: the second is as likely to be this service
     * having built a bad request as the install being gone.
     */
    private static Outcome outcome(int status, String body) {
        if (status >= 200 && status < 300) {
            return Outcome.DELIVERED;
        }
        if (status == 404 || (body != null && body.contains("UNREGISTERED"))) {
            return Outcome.UNREGISTERED;
        }
        log.warn("FCM refused an authority alert with status {}", status);
        return Outcome.RETRYABLE;
    }

    private static String payload(String token, String title, String body) {
        return "{\"message\":{\"token\":" + json(token)
                + ",\"notification\":{\"title\":" + json(title) + ",\"body\":" + json(body) + "}"
                + ",\"android\":{\"priority\":\"HIGH\"}}}";
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

    private FcmProperties fcm() {
        return properties.getAuthority().getNotifications().getFcm();
    }
}
