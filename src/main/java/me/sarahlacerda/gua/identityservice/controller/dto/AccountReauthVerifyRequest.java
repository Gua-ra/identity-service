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
    @Schema(description = "6-digit OTP delivered via SMS to the linked phone number", example = "123456")
    private String code;

    /**
     * Operation the issued token may be spent on. Binding the token to a single
     * operation closes a confused-deputy hole (a deactivate token must not be
     * spendable on a phone change). Defaults to {@code DEACTIVATE} to keep existing
     * deactivate/reset clients working while new flows request {@code PHONE_CHANGE}.
     */
    @Schema(description = "Privileged operation the token will authorize", example = "PHONE_CHANGE",
            defaultValue = "DEACTIVATE")
    private ReauthOperation operation = ReauthOperation.DEACTIVATE;
}
