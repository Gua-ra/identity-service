package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import io.swagger.v3.oas.annotations.media.Schema;

@Getter
@Setter
@Schema(description = "Payload to start an account reauthentication by confirming the account's current number")
public class AccountReauthStartRequest {

    /**
     * The number the signed-in user says is on their account. It is normalized, digested and
     * compared with that account's own directory binding; only a match sends a code, and the
     * code goes to that number. Nothing is stored, and the refusal never says whether the
     * number belongs to somebody else.
     */
    @NotBlank
    @Schema(description = "The account's current phone number, E.164 or a national number", example = "+14155550123")
    private String phone;
}
