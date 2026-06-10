package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import io.swagger.v3.oas.annotations.media.Schema;

@Getter
@Setter
@Schema(description = "Payload to verify the reauth OTP and exchange it for a reauth token")
public class AccountReauthVerifyRequest {

    @NotBlank
    @Schema(description = "6-digit OTP delivered via SMS to the linked phone number", example = "123456")
    private String code;
}
