// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * A started approval.
 *
 * @param code four characters from an alphabet with no look-alikes, which the device shows too. It is the
 *             whole of what binds the two screens together, so it is never reused among an account's live
 *             approvals
 */
@Schema(description = "A pending approval a browser shows and an authority device signs")
public record AuthorityApprovalResponse(String approvalId, String code, String challenge,
        long expiresInSeconds) {
}
