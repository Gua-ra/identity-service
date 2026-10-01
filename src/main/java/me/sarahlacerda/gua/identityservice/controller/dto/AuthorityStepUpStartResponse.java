// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
@Schema(description = "Result of starting an authority web step-up. The client opens stepUpUrl in a web sheet "
        + "and waits for the redirect back to its own scheme, then asks for the challenge as usual.")
public class AuthorityStepUpStartResponse {

    @Schema(description = "Absolute, one-time URL on the sign-in web origin that establishes the login cookie "
            + "and renders the authority step-up",
            example = "https://auth.example.com/login/enroll/AbCd...")
    private final String stepUpUrl;
}
