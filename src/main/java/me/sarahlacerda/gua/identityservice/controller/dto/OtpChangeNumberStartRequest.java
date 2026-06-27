package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import io.swagger.v3.oas.annotations.media.Schema;

@Getter
@Setter
@Schema(description = "Request to send an OTP to a new phone number after a PIN step-up, gated by a reauth token")
public class OtpChangeNumberStartRequest {

    @NotBlank
    @Schema(description = "Matrix user identifier that is changing phones", example = "@user:gua.global")
    private String userId;

    @NotBlank
    @Schema(description = "New phone number in E.164 format to send the OTP to", example = "+14155550123")
    private String newPhone;

    @NotBlank
    @Schema(description = "Single-use reauth token from /security/pin/reauth proving a fresh PIN step-up", example = "x9c2...")
    private String reauthToken;

    @Schema(description = "Optional language preference for the OTP SMS", example = "pt-BR")
    private String language;
}
