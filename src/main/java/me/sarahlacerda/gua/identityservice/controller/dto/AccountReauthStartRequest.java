package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import io.swagger.v3.oas.annotations.media.Schema;

@Getter
@Setter
@Schema(description = "Payload to start an account reauthentication by confirming the account's current number")
public class AccountReauthStartRequest {

    @NotBlank
    @Schema(description = "The account's current phone number, E.164 or a national number", example = "+14155550123")
    private String phone;
}
