package me.sarahlacerda.gua.identityservice.controller.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import io.swagger.v3.oas.annotations.media.Schema;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Result of an OTP verification. For existing users contains a Matrix session, " +
        "for new users a signupToken to complete signup, and for returning users with two-step verification a pinChallengeToken "
        +
        "to redeem at /signin/verify-pin.")
public record OtpVerifyResponse(
        @Schema(description = "Matrix access token (existing user only)", example = "MDAxY2x...") String accessToken,
        @Schema(description = "Matrix user identifier (existing user only)", example = "@alice:gua.global") String userId,
        @Schema(description = "Matrix device identifier (existing user only)", example = "DEVICEID") String deviceId,
        @Schema(description = "Base URL of the homeserver (existing user only)", example = "https://matrix-client.dev.gua") String baseUrl,
        @Schema(description = "True when the phone has no associated account; client must call /signup/complete next") Boolean isNewUser,
        @Schema(description = "Short-lived token to pass back to /signup/complete (new users only)") String signupToken,
        @Schema(description = "True when the user has two-step verification enabled; client must call /signin/verify-pin next") Boolean pinRequired,
        @Schema(description = "Short-lived token to pass back to /signin/verify-pin (returning users with a PIN only)") String pinChallengeToken) {

    public static OtpVerifyResponse existingUser(String accessToken, String userId, String deviceId, String baseUrl) {
        return new OtpVerifyResponse(accessToken, userId, deviceId, baseUrl, Boolean.FALSE, null, Boolean.FALSE, null);
    }

    public static OtpVerifyResponse newUser(String signupToken) {
        return new OtpVerifyResponse(null, null, null, null, Boolean.TRUE, signupToken, Boolean.FALSE, null);
    }

    public static OtpVerifyResponse pinRequired(String pinChallengeToken) {
        return new OtpVerifyResponse(null, null, null, null, Boolean.FALSE, null, Boolean.TRUE, pinChallengeToken);
    }
}
