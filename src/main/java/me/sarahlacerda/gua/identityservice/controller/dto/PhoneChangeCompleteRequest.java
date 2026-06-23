package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

/**
 * Step 2 of a phone-number change. The challenge id (issued by /start) is the
 * proof that re-auth + step-up already succeeded; the OTP confirms possession of
 * the new number. On success the account's phone mapping is atomically switched.
 */
@Getter
@Setter
@Schema(description = "Complete a phone-number change with the challenge id and the new-number OTP")
public class PhoneChangeCompleteRequest {

    @NotBlank
    @Schema(description = "Challenge id returned by /account/phone/change/start", example = "1c1d2e3f-...")
    private String challengeId;

    @NotBlank
    @Schema(description = "OTP delivered via SMS to the new phone number", example = "654321")
    private String code;
}
