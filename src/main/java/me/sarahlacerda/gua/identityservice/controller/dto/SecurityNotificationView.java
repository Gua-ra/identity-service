// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * One registration, as its own account holder is allowed to see it.
 *
 * <p>The token is never here, in either direction. The fingerprint column exists precisely so a registration
 * can be named in a listing, a log line or a support conversation without the destination itself being handed
 * back out.
 */
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
