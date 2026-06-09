package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import io.swagger.v3.oas.annotations.media.Schema;

@Getter
@Setter
@Schema(description = "Payload to deactivate the calling user's Matrix account")
public class AccountDeactivateRequest {

    @NotBlank
    @Schema(description = "Single-use reauth token issued by /account/reauth/verify")
    private String reauthToken;

    @Schema(description = "When true, the homeserver wipes profile data and outbound keys (GDPR erase)", example = "false")
    private boolean eraseData;
}
