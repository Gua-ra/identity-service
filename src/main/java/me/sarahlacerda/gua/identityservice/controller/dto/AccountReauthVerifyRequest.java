package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import io.swagger.v3.oas.annotations.media.Schema;

import me.sarahlacerda.gua.identityservice.service.security.ReauthOperation;

@Getter
@Setter
@Schema(description = "Payload to verify the reauth OTP and exchange it for a reauth token")
public class AccountReauthVerifyRequest {

    @NotBlank
    @Schema(description = "The account's current phone number, E.164 or a national number", example = "+14155550123")
    private String phone;

    @NotBlank
    @Schema(description = "6-digit OTP delivered via SMS to the account's number", example = "123456")
    private String code;

    /** Defaults to DEACTIVATE so older clients keep working. */
    @Schema(description = "Privileged operation the token will authorize", example = "PHONE_CHANGE",
            defaultValue = "DEACTIVATE")
    private ReauthOperation operation = ReauthOperation.DEACTIVATE;
}
