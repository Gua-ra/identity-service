// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;

import io.swagger.v3.oas.annotations.media.Schema;

/** One active device's signature over exactly this approval. */
@Schema(description = "An authority device's signature over one pending approval")
public class AuthorityApprovalSignRequest {

    @NotBlank
    @Schema(description = "Signature over the approval domain, the account, the approval id, the action digest "
            + "and the challenge", requiredMode = Schema.RequiredMode.REQUIRED)
    private String signature;

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }
}
