package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import io.swagger.v3.oas.annotations.media.Schema;

@Getter
@Setter
@Schema(description = "Request used to bind a newly verified phone number to an existing user")
public class OtpChangeNumberRequest {

    @NotBlank
    @Schema(description = "Matrix user identifier that is changing phones", example = "@user:gua.global")
    private String userId;

    @NotBlank
    @Schema(description = "New phone number in E.164 format", example = "+14155550123")
    private String newPhone;

    @NotBlank
    @Schema(description = "OTP that confirms ownership of the new phone", example = "654321")
    private String code;

    @NotBlank
    @Schema(description = "Existing account PIN used as a second factor", example = "123456")
    private String pin;
}
