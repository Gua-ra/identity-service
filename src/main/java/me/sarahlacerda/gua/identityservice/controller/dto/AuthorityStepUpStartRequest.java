// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotNull;

import io.swagger.v3.oas.annotations.media.Schema;

import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;

@Schema(description = "Start the web step-up for one authority transition")
public class AuthorityStepUpStartRequest {

    @NotNull
    @Schema(description = "ADOPT, GRANT, REVOKE or RECOVER. The purposes that ask for no factor are refused "
            + "with authority_step_up_purpose_refused.", requiredMode = Schema.RequiredMode.REQUIRED)
    private Purpose purpose;

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
