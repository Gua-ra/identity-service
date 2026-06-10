package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import io.swagger.v3.oas.annotations.media.Schema;

@Getter
@Setter
@Schema(description = "Payload to mint a fresh User-Interactive Authentication credential for identity reset")
public class IdentityResetCredentialsRequest {

    @NotBlank
    @Schema(description = "Single-use reauth token issued by /account/reauth/verify")
    private String reauthToken;
}
