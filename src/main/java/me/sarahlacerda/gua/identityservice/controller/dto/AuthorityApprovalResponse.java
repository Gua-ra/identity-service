// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "A pending approval a browser shows and an authority device signs")
public record AuthorityApprovalResponse(String approvalId, String code, String challenge,
        long expiresInSeconds) {
}
