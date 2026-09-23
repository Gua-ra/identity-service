// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import com.fasterxml.jackson.databind.JsonNode;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Getter;
import lombok.Setter;

/**
 * What a removal presents (ADM-009 gate 2, the three tiers).
 *
 * <p>Which tier the caller reaches is decided by what they can produce and never by a field they set. Naming
 * your own install in {@code callerInstallationId} and in {@code installationId} is tier 1 and needs nothing
 * else; naming another install is tier 2 and needs a factor past the fresh-factor hold, plus a device
 * signature where the row carries a key. There is no third tier, no admin path and no bulk delete.
 */
@Getter
@Setter
@Schema(description = "A request to remove one security-notification registration")
public class SecurityNotificationRemoveRequest {

    @NotBlank
    @Size(max = 128)
    @Schema(description = "The install whose registration is being removed",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String installationId;

    @Size(max = 128)
    @Schema(description = "The calling app's own installation id. When it equals installationId the caller is "
            + "removing its own registration, which needs no extra factor.")
    private String callerInstallationId;

    @Schema(description = "A step-up assertion id, for removing another install's registration")
    private String passkeyStepUpId;

    @Schema(description = "The passkey assertion, for removing another install's registration")
    private JsonNode passkeyCredential;

    @Schema(description = "The account PIN, where no passkey assertion is presented. Refused while it is "
            + "inside the fresh-factor hold, which is what stops a just-recovered account emptying the channel.")
    private String pin;

    @Schema(description = "A challenge minted for purpose NOTIFY, required when the row carries a device key")
    private String challenge;

    @Schema(description = "Ed25519 by the device key on the row, over the gua-authority-notification.v1 "
            + "preimage, required when the row carries one")
    private String signature;
}
