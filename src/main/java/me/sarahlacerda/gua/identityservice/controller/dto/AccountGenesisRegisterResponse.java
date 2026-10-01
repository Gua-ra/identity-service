package me.sarahlacerda.gua.identityservice.controller.dto;

import java.time.Instant;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "A registered accountId and its single-use attach handle")
public record AccountGenesisRegisterResponse(
        @Schema(description = "The derived accountId", example = "ga1aea6aqb5opmzmutench3ggzepkhgwmkajb3epqqrhckkf7bcbcwl2cy")
        String accountId,

        @Schema(description = "Single-use handle to send as login_hint=\"gua:phone=<E.164>;genesis=<handle>\"")
        String attachHandle,

        @Schema(description = "When the handle stops being attachable")
        Instant expiresAt) {
}
