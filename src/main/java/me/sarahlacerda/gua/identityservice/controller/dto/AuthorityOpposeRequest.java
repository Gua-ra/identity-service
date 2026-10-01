// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import com.fasterxml.jackson.databind.JsonNode;

import io.swagger.v3.oas.annotations.media.Schema;

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
