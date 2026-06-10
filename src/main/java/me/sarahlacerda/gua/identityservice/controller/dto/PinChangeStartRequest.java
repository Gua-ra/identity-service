package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Schema(description = "Request to start a PIN change. Verifies the current PIN and sends an OTP to the verified phone.")
public class PinChangeStartRequest {

    @NotBlank
    @Schema(description = "Verified phone number that will receive the OTP", example = "+5511987654321")
    private String phone;

    @NotBlank
    @Pattern(regexp = "\\d{6}", message = "PIN must be 6 digits")
    @Schema(description = "Current PIN to authorize the change", example = "123456")
    private String currentPin;
}
