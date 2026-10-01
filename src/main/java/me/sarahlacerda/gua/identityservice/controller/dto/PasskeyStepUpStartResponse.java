package me.sarahlacerda.gua.identityservice.controller.dto;

import com.fasterxml.jackson.databind.JsonNode;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "WebAuthn request options for a user-verifying step-up assertion")
public record PasskeyStepUpStartResponse(
        @Schema(description = "Identifier of this step-up ceremony. Send it back with the assertion "
                + "response on the operation being stepped up.") String stepUpId,

        @Schema(description = "The WebAuthn publicKey request options to hand to the authenticator") JsonNode publicKey) {
}
