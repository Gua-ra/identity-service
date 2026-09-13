package me.sarahlacerda.gua.identityservice.controller.dto;

import com.fasterxml.jackson.databind.JsonNode;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Options for a passkey ceremony whose assertion may be spent as the step-up factor
 * on a privileged operation. The ceremony demands user verification, so a response
 * that only proves possession of the device is refused when the assertion is
 * redeemed.
 */
@Schema(description = "WebAuthn request options for a user-verifying step-up assertion")
public record PasskeyStepUpStartResponse(
        @Schema(description = "Identifier of this step-up ceremony. Send it back with the assertion "
                + "response on the operation being stepped up.") String stepUpId,

        @Schema(description = "The WebAuthn publicKey request options to hand to the authenticator") JsonNode publicKey) {
}
