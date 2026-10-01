// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import com.fasterxml.jackson.databind.JsonNode;

import jakarta.validation.constraints.NotNull;

import io.swagger.v3.oas.annotations.media.Schema;

import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;

/**
 * Must not gain a phone-code field or a "factor unavailable" flag: either would let a caller downgrade
 * the step-up.
 */
@Schema(description = "Request a server challenge for one authority transition, after a scoped step-up")
public class AuthorityChallengeRequest {

    @NotNull
    @Schema(description = "What the challenge may be spent on", requiredMode = Schema.RequiredMode.REQUIRED)
    private Purpose purpose;

    @Schema(description = "Id from POST /security/passkey/stepup/options, with the assertion below")
    private String passkeyStepUpId;

    @Schema(description = "The user-verifying passkey assertion. Settles the step-up on its own")
    private JsonNode passkeyCredential;

    @Schema(description = "The account PIN, when no passkey assertion is offered")
    private String pin;

    public Purpose getPurpose() {
        return purpose;
    }

    public void setPurpose(Purpose purpose) {
        this.purpose = purpose;
    }

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
