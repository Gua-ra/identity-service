// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Getter;
import lombok.Setter;

/**
 * What an install registers as a security-notification destination (ADM-009 gate 2).
 *
 * <p>The installation id is the field that matters. It is client-generated, held in the keychain or keystore
 * rather than in preferences, and stable across sign-out and re-login, which is what lets the row outlive the
 * sessions an account recovery ends. The nearest existing thing, the pusher profile tag, lives in user
 * defaults and dies with the app data, so it could not carry this.
 */
@Getter
@Setter
@Schema(description = "One install's security-notification destination")
public class SecurityNotificationRegisterRequest {

    @NotBlank
    @Size(max = 128)
    @Schema(description = "Client-generated id of this install, held in the keychain or keystore and stable "
            + "across sign-out. The upsert key.", requiredMode = Schema.RequiredMode.REQUIRED)
    private String installationId;

    @NotBlank
    @Schema(description = "APNS or FCM", requiredMode = Schema.RequiredMode.REQUIRED)
    private String platform;

    @NotBlank
    @Size(max = 4096)
    @Schema(description = "The APNs device token or FCM registration token. Stored, never logged, and never "
            + "returned.", requiredMode = Schema.RequiredMode.REQUIRED)
    private String token;

    @NotBlank
    @Size(max = 128)
    @Schema(description = "The same app id the Matrix pusher already sends, so the topic or project is picked "
            + "from one constant.", requiredMode = Schema.RequiredMode.REQUIRED)
    private String appId;

    @Size(max = 64)
    @Schema(description = "At most the 16 bytes of UTF-8 a record's label may carry, because that is all a "
            + "notification is allowed to name")
    private String deviceLabel;

    @Size(max = 64)
    @Schema(description = "Optional: the device authority key this install holds, base64url. Accepted only "
            + "with a challenge and a signature by that key, because the field is what makes removing this "
            + "registration from another install need a signature.")
    private String authorityDeviceKeyB64;

    @Schema(description = "A challenge minted for purpose NOTIFY, required with authorityDeviceKeyB64")
    private String challenge;

    @Schema(description = "Ed25519 over the gua-authority-notification.v1 preimage, required with "
            + "authorityDeviceKeyB64")
    private String signature;
}
