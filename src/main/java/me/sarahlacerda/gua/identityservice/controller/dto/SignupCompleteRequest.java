package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

import io.swagger.v3.oas.annotations.media.Schema;

@Getter
@Setter
@Schema(description = "Payload to finalize signup for a new user after OTP verification")
public class SignupCompleteRequest {

    @NotBlank
    @Schema(description = "Short-lived token returned by /otp/verify when isNewUser is true", required = true)
    private String signupToken;

    @NotBlank
    @Size(min = 3, max = 30)
    @Schema(description = "Chosen Matrix localpart. Lowercase letters, digits, dot, underscore, or dash.", example = "sarah_l", required = true)
    private String username;

    @NotBlank
    @Size(min = 1, max = 80)
    @Schema(description = "Chosen Matrix display name.", example = "Sarah Lacerda", required = true)
    private String displayName;

    @Schema(description = "Optional security PIN to set on the new account", example = "654321")
    private String pin;

    @Valid
    @Schema(description = "Metadata about the device requesting the session")
    private OtpVerifyRequest.DeviceInfo device;
}
