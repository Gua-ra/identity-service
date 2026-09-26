// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import com.fasterxml.jackson.databind.JsonNode;

import jakarta.validation.constraints.NotNull;

import io.swagger.v3.oas.annotations.media.Schema;

import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;

/**
 * Asks for the server challenge one authority transition will sign (ADM-009 decision 2).
 *
 * <p>The step-up travels in this body, which is the house pattern: the phone change and the PIN change carry
 * their step-up in the request of the operation they authorize rather than exchanging it for a token first.
 * Here it is more than a convention. The challenge is minted in the same call as the step-up, so ADM-009
 * decision 4's "a step-up no older than the challenge" holds by construction: there is no step-up artifact
 * that outlives the challenge and nothing to compare two ages of.
 *
 * <p>There is no field for a phone code, and there is no field for saying a factor is unavailable on this
 * device. Both absences are the point: an SMS code proves possession of a number, which a SIM swap also
 * gives, and a claim that a factor cannot be produced costs an attacker nothing.
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
