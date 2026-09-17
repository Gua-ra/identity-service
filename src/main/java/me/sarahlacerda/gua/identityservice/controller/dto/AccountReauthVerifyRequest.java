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

    /**
     * The account's current number again. Checked the same way as at
     * {@code /account/reauth/start}: nothing was stored between the two calls, so the token can
     * only be minted by someone who can produce both the number and the code sent to it.
     */
    @NotBlank
    @Schema(description = "The account's current phone number, E.164 or a national number", example = "+14155550123")
    private String phone;

    @NotBlank
    @Schema(description = "6-digit OTP delivered via SMS to the account's number", example = "123456")
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
