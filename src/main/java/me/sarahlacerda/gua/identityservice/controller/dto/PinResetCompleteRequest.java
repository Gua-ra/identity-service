package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

import io.swagger.v3.oas.annotations.media.Schema;

@Getter
@Setter
@Schema(description = "Request used to finalize a PIN reset after OTP verification")
public class PinResetCompleteRequest {

    @NotBlank
    @Schema(description = "Matrix user identifier", example = "@user:gua.global")
    private String userId;

    @NotBlank
    @Schema(description = "Phone number that received the reset OTP", example = "+14155550123")
    private String phone;

    @NotBlank
    @Schema(description = "OTP sent to the phone to authorize the reset", example = "789456")
    private String code;

    @NotBlank
    @Pattern(regexp = "\\d{6}", message = "PIN must be 6 digits")
    @Schema(description = "New PIN that will replace the existing one", example = "112233")
    private String newPin;
}
