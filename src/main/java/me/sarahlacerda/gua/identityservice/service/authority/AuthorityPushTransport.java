// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.net.http.HttpClient;
import java.time.Duration;

import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration.Platform;

public interface AuthorityPushTransport {

    /** Payload key clients use to tell an authority alert from a Matrix push. */
    String ALERT_MARKER = "gua_authority_alert";

    Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);

    Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    static HttpClient.Builder httpClient() {
        return HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT);
    }

    Platform platform();

    boolean isConfigured();

    Outcome send(String token, String appId, String title, String body);

    enum Outcome {
        DELIVERED,
        RETRYABLE,
        UNREGISTERED
    }
}
