package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Single-use opaque token spendable on one privileged account endpoint")
public record AccountReauthTokenResponse(
        @Schema(description = "Opaque token to pass to /account/deactivate or similar endpoints") String reauthToken,
        @Schema(description = "Token lifetime in seconds", example = "300") long expiresInSeconds) {
}
