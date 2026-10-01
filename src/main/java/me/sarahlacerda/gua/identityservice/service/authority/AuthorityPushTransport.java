// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import me.sarahlacerda.gua.identityservice.domain.AuthorityNotificationRegistration.Platform;

public interface AuthorityPushTransport {

    /** Payload key clients use to tell an authority alert from a Matrix push. */
    String ALERT_MARKER = "gua_authority_alert";

    Platform platform();

    boolean isConfigured();

    Outcome send(String token, String appId, String title, String body);

    enum Outcome {
        DELIVERED,
        RETRYABLE,
        UNREGISTERED
    }
}
