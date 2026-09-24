// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotNull;

import io.swagger.v3.oas.annotations.media.Schema;

import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;

/**
 * Asks for the one-time URL of a web step-up scoped to one authority transition (ADM-009 decision 4 step 2).
 *
 * <p>Two fields, and nothing else. There is no field for a phone number, because no arm of that page sends a
 * code. There is no field for saying which factor the device can produce, because a claim that a factor is
 * unavailable costs an attacker nothing and could only ever ask for something weaker: the page offers the
 * passkey when the account holds one and the PIN when it holds one, from what the server knows.
 */
@Schema(description = "Start the web step-up for one authority transition")
public class AuthorityStepUpStartRequest {

    /**
     * The transition this step-up will authorize. A proof taken for one purpose is not a proof for another, so
     * this is stamped on the session and compared again when the challenge endpoint spends it.
     */
    @NotNull
    @Schema(description = "ADOPT, GRANT, REVOKE or RECOVER. The purposes that ask for no factor are refused "
            + "with authority_step_up_purpose_refused.", requiredMode = Schema.RequiredMode.REQUIRED)
    private Purpose purpose;

    /**
     * Where the sheet hands back to when the step-up completes: the app scheme this build answers, bounded by
     * the same deployment allowlist factor enrollment uses. Omit it to take the deployment's own resolution.
     */
    @Schema(description = "App-scheme redirect this build answers. Must be one the deployment allows.",
            example = "global.gua.dev:/oidc")
    private String redirectUri;

    public Purpose getPurpose() {
        return purpose;
    }

    public void setPurpose(Purpose purpose) {
        this.purpose = purpose;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }
}
