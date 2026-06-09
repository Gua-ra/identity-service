package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Ephemeral credentials the client feeds into Matrix UIA m.login.password to complete identity reset")
public record IdentityResetCredentialsResponse(
        @Schema(description = "Matrix user id (e.g. @user:server)") String userId,
        @Schema(description = "One-time password the SDK should send in the UIA m.login.password stage") String password) {
}
