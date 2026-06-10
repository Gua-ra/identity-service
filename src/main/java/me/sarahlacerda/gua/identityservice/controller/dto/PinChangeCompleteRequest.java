package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema(description = "Request to finalize a PIN change started via /security/pin/change/start.")
public class PinChangeCompleteRequest {

    @NotBlank
    @Schema(description = "Challenge identifier returned by /security/pin/change/start", example = "1c1d2e3f-...")
    private String challengeId;

    @NotBlank
    @Schema(description = "OTP delivered to the verified phone", example = "123456")
    private String otpCode;

    @NotBlank
    @Pattern(regexp = "\\d{6}", message = "PIN must be 6 digits")
    @Schema(description = "New 6-digit PIN to store", example = "654321")
    private String newPin;
}
