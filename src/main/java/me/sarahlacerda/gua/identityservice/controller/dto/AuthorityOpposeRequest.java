// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import com.fasterxml.jackson.databind.JsonNode;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Objects to the transition holding a slot on this account (ADM-009 decision 4).
 *
 * <p>The record hash is accepted and deliberately not used to select what is cancelled: an opposition cancels
 * every pending adoption on the account, not only the one it names. One pending transition per account is the
 * rule, so the difference is invisible in normal operation and decisive if it is ever not.
 *
 * <p>The step-up fields are for the second and later opposition. The first is deliberately cheap, because at
 * {@code seq = 1} the account holds no authority to weigh. The fresh-factor hold is never applied here: it
 * gates starting a transition and never opposing one, so an owner who has just changed their PIN to lock a
 * thief out is not the one disarmed by it.
 */
@Schema(description = "Object to the pending authority transition on this account")
public class AuthorityOpposeRequest {

    @Schema(description = "The pending record's hash, as GET /account/authority reports it")
    private String recordHash;

    @Schema(description = "Second and later oppositions: a step-up on any factor, at any age")
    private String passkeyStepUpId;

    @Schema(description = "Second and later oppositions: the passkey assertion")
    private JsonNode passkeyCredential;

    @Schema(description = "Second and later oppositions: the account PIN")
    private String pin;

    public String getRecordHash() {
        return recordHash;
    }

    public void setRecordHash(String recordHash) {
        this.recordHash = recordHash;
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
