package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Result of starting a phone-number change. Holds the challenge id the client
 * redeems at /account/phone/change/complete together with the OTP delivered to
 * the new number.
 */
@Getter
@RequiredArgsConstructor
@Schema(description = "Result of starting a phone-number change")
public class PhoneChangeStartResponse {

    @Schema(description = "Opaque challenge id proving step-up succeeded and an OTP was sent to the new number",
            example = "1c1d2e3f-...")
    private final String challengeId;

    @Schema(description = "Seconds before the new-number OTP expires", example = "300")
    private final long otpExpiresInSeconds;
}
