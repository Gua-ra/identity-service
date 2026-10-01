// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "A live approval waiting for an authority device")
public record AuthorityApprovalView(String approvalId, String code, String action, String actionDigest,
        String challenge, long expiresAtEpochSeconds) {
}
