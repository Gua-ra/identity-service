// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "A single-use server challenge, held against this account and this session")
public record AuthorityChallengeResponse(String challenge, long expiresInSeconds) {
}
