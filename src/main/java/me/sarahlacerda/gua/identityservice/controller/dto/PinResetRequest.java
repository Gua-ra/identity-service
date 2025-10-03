package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import io.swagger.v3.oas.annotations.media.Schema;

@Getter
@Setter
@Schema(description = "Request to initiate a security PIN reset")
public class PinResetRequest {

    @NotBlank
    @Schema(description = "Matrix user identifier", example = "@user:gua.global")
    private String userId;

    @NotBlank
    @Schema(description = "Verified phone number that will receive the reset OTP", example = "+5511987654321")
    private String phone;
}
