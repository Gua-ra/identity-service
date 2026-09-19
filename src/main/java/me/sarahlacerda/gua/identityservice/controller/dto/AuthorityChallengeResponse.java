// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * The 32 challenge bytes, returned once.
 *
 * @param challenge        base64url without padding. Only its SHA-256 is stored, so this is the only time
 *                         the value exists outside the caller
 * @param expiresInSeconds how long it stays spendable, which is also the age limit on the step-up that
 *                         minted it
 */
@Schema(description = "A single-use server challenge, held against this account and this session")
public record AuthorityChallengeResponse(String challenge, long expiresInSeconds) {
}
