// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "The outcome of submitting one authority record")
public record AuthoritySubmissionResponse(long seq, String state, long effectiveAtEpochSeconds,
        String recordHash) {
}
