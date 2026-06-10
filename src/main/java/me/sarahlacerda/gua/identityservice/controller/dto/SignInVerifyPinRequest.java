package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
@Schema(description = "Second leg of the phone sign-in flow for users with two-step verification enabled.")
public class SignInVerifyPinRequest {

    @NotBlank
    @Schema(description = "Short-lived token returned by /otp/verify when pinRequired=true", example = "Q1c4...3xS")
    private String pinChallengeToken;

    @NotBlank
    @Pattern(regexp = "\\d{6}", message = "PIN must be 6 digits")
    @Schema(description = "The user's 6-digit account PIN", example = "654321")
    private String pin;

    @Schema(description = "Optional metadata about the device performing sign-in")
    private OtpVerifyRequest.DeviceInfo device;
}
