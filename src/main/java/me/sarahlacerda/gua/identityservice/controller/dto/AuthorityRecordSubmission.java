// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;

import io.swagger.v3.oas.annotations.media.Schema;

/** The client returns the challenge because the server stores only its hash. */
@Schema(description = "A signed authority record and the challenge inside its signature")
public class AuthorityRecordSubmission {

    @NotBlank
    @Schema(description = "The canonical record bytes, base64url without padding",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String record;

    @NotBlank
    @Schema(description = "The detached 64-byte Ed25519 signature over magic, challenge and canonical bytes",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String signature;

    @NotBlank
    @Schema(description = "The challenge from POST /account/authority/challenge, base64url",
            requiredMode = Schema.RequiredMode.REQUIRED)
    private String challenge;

    @Schema(description = "Adoption only: that the recovery key was shown and the holder confirmed storing it")
    private boolean recoveryArtifactConfirmed;

    public String getRecord() {
        return record;
    }

    public void setRecord(String record) {
        this.record = record;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public boolean isRecoveryArtifactConfirmed() {
        return recoveryArtifactConfirmed;
    }

    public void setRecoveryArtifactConfirmed(boolean recoveryArtifactConfirmed) {
        this.recoveryArtifactConfirmed = recoveryArtifactConfirmed;
    }
}
