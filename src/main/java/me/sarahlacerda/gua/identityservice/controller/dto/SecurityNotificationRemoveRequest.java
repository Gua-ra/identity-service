// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import com.fasterxml.jackson.databind.JsonNode;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import io.swagger.v3.oas.annotations.media.Schema;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema(description = "A request to remove one security-notification registration")
public class SecurityNotificationRemoveRequest {

    @NotBlank
    @Size(max = 128)
    @Schema(description = "The install whose registration is being removed",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String installationId;

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
