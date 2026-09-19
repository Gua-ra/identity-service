package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
@Schema(description = "Result of starting in-app PIN enrollment. The client opens enrollUrl in an authenticated web view, which confirms the account before the PIN is set.")
public class PinEnrollStartResponse {

    @Schema(description = "Absolute, one-time URL on the sign-in web origin that establishes the login cookie and renders the enrollment step-up", example = "https://auth.example.com/login/enroll/AbCd...")
    private final String enrollUrl;
}
