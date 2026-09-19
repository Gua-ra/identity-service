// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import com.fasterxml.jackson.databind.JsonNode;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Removes one passkey credential, with the step-up that authorizes it.
 *
 * <p>There is no field for saying a passkey is unavailable on this device, only the absence of an assertion,
 * and the PIN branch is never removed. That claim costs an attacker nothing, which is why no request in this
 * service accepts it.
 */
@Schema(description = "Remove one passkey credential after a step-up")
public class PasskeyRemoveRequest {

    @Schema(description = "Id from POST /security/passkey/stepup/options, with the assertion below")
    private String passkeyStepUpId;

    @Schema(description = "The user-verifying passkey assertion. Settles the step-up on its own")
    private JsonNode passkeyCredential;

    @Schema(description = "The account PIN, when no passkey assertion is offered")
    private String pin;

    public String getPasskeyStepUpId() {
        return passkeyStepUpId;
    }

    public void setPasskeyStepUpId(String passkeyStepUpId) {
        this.passkeyStepUpId = passkeyStepUpId;
    }

    public JsonNode getPasskeyCredential() {
        return passkeyCredential;
    }

    public void setPasskeyCredential(JsonNode passkeyCredential) {
        this.passkeyCredential = passkeyCredential;
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }
}
