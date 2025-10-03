package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import io.swagger.v3.oas.annotations.media.Schema;

@Getter
@Setter
@Schema(description = "Payload used to request that an OTP SMS be sent to a phone number")
public class OtpSendRequest {

    @NotBlank
    @Schema(description = "Target phone number in E.164 format", example = "+5511987654321")
    private String phone;

    @Schema(description = "Optional BCP 47 language tag indicating the preferred SMS language", example = "pt-BR")
    private String language;
}
