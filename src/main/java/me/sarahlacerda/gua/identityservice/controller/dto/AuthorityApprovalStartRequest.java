// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Starts an approval for an authority-sensitive action a browser session wants (ADM-009 decision 6).
 *
 * <p>The action is what makes the approval specific, and it is what the authority device describes in the
 * reader's own words on a screen the page does not control. A malicious page can reach this endpoint; what it
 * cannot reach is the signature.
 *
 * <p>There is deliberately no {@code actionDigest} field. The digest the device signs over is derived from
 * the action by the server, because two caller-chosen values would let the sentence shown to the reader and
 * the bytes covered by the signature be different actions.
 */
@Schema(description = "Start an approval a browser session cannot grant itself")
public class AuthorityApprovalStartRequest {

    @NotBlank
    @Schema(description = "Opaque action id, which the device describes to the reader and whose digest it "
            + "signs over", requiredMode = Schema.RequiredMode.REQUIRED)
    private String action;

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }
}
