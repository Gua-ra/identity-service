package me.sarahlacerda.gua.identityservice.controller.dto;

import java.time.Instant;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * The registered accountId and the single-use handle that lets the next login session claim it.
 *
 * <p>The handle is a routing hint, not a capability: a stolen one attaches nothing and a planted one
 * fails at the proof step, because the attach also needs a signature over server-chosen bytes bound to
 * that login session (ADM-008 decision 6).
 */
@Schema(description = "A registered accountId and its single-use attach handle")
public record AccountGenesisRegisterResponse(
        @Schema(description = "The derived accountId", example = "ga1aea6aqb5opmzmutench3ggzepkhgwmkajb3epqqrhckkf7bcbcwl2cy")
        String accountId,

        @Schema(description = "Single-use handle to send as login_hint=\"gua:phone=<E.164>;genesis=<handle>\"")
        String attachHandle,

        @Schema(description = "When the handle stops being attachable")
        Instant expiresAt) {
}
