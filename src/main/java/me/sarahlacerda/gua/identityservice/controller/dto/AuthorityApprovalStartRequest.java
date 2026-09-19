// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Starts an approval for an authority-sensitive action a browser session wants (ADM-009 decision 6).
 *
 * <p>The digest is what makes the approval specific, and it is what the authority device describes in the
 * reader's own words on a screen the page does not control. A malicious page can reach this endpoint; what it
 * cannot reach is the signature.
 */
@Schema(description = "Start an approval a browser session cannot grant itself")
public class AuthorityApprovalStartRequest {

    @Schema(description = "Opaque action id, for the device to describe the action")
    private String action;

    @NotBlank
    @Schema(description = "SHA-256 of the exact action, base64url", requiredMode = Schema.RequiredMode.REQUIRED)
    private String actionDigest;

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getActionDigest() {
        return actionDigest;
    }

    public void setActionDigest(String actionDigest) {
        this.actionDigest = actionDigest;
    }
}
