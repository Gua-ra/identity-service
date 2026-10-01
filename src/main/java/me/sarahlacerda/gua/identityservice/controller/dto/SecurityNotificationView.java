// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import io.swagger.v3.oas.annotations.media.Schema;

/** Never exposes the push token, only its fingerprint. */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "A security-notification registration, without its destination")
public record SecurityNotificationView(
        @Schema(description = "The install this registration belongs to") String installationId,
        @Schema(description = "APNS or FCM") String platform,
        @Schema(description = "The label a notification may name") String deviceLabel,
        @Schema(description = "SHA-256 hex of the token, so a row can be named without printing it")
        String tokenFingerprint,
        @Schema(description = "Whether removing it from another install needs a device signature")
        boolean boundToAnAuthorityDevice,
        @Schema(description = "When the server last heard from this install") long lastSeenAtEpochSeconds) {
}
