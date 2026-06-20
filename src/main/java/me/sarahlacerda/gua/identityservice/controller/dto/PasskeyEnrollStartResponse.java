package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
@Schema(description = "Result of starting in-app passkey enrollment. The client opens enrollUrl in an authenticated web view to run the passkey setup ceremony.")
public class PasskeyEnrollStartResponse {

    @Schema(description = "Absolute, one-time URL on the sign-in web origin that establishes the login cookie and renders the passkey setup step", example = "https://auth.example.com/login/passkey/enroll/AbCd...")
    private final String enrollUrl;
}
