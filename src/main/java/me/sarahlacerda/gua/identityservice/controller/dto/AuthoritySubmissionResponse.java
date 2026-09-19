// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * What a submitted record did.
 *
 * @param seq                     the position it took, which it holds even if it is later cancelled
 * @param state                   PENDING while its window runs, ACTIVE when it took effect on acceptance
 * @param effectiveAtEpochSeconds when it completes, or when it completed
 * @param recordHash              SHA-256 hex over its canonical bytes, which an opposition names
 */
@Schema(description = "The outcome of submitting one authority record")
public record AuthoritySubmissionResponse(long seq, String state, long effectiveAtEpochSeconds,
        String recordHash) {
}
