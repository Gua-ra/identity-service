package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
@Schema(description = "Result of starting a PIN change. Holds the challenge to redeem at /security/pin/change/complete.")
public class PinChangeStartResponse {

    @Schema(description = "Opaque identifier proving the current PIN was verified and an OTP was sent", example = "1c1d2e3f-...")
    private final String challengeId;

    @Schema(description = "Number of seconds before the challenge expires", example = "300")
    private final long expiresInSeconds;
}
