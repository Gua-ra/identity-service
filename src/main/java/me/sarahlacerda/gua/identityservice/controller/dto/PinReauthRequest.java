package me.sarahlacerda.gua.identityservice.controller.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import io.swagger.v3.oas.annotations.media.Schema;

@Getter
@Setter
@Schema(description = "PIN step-up payload exchanged for a single-use reauth token")
public class PinReauthRequest {

    @NotBlank
    @Schema(description = "Matrix user identifier performing the PIN step-up", example = "@user:gua.global")
    private String userId;

    @NotBlank
    @Schema(description = "Existing account PIN used to step up", example = "123456")
    private String pin;
}
