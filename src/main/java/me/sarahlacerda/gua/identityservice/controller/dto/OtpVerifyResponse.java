package me.sarahlacerda.gua.identityservice.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Matrix access token issued after successful OTP verification")
public record OtpVerifyResponse(
    @Schema(description = "Matrix access token", example = "MDAxY2x...") String accessToken,
    @Schema(description = "Matrix user identifier associated with the session", example = "@user:gua.global") String userId,
    @Schema(description = "Matrix device identifier created during login", example = "DEVICEID") String deviceId,
    @Schema(description = "Base URL of the homeserver clients should target", example = "https://matrix-client.dev.gua") String baseUrl
) {}
