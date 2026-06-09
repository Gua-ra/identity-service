package me.sarahlacerda.gua.identityservice.domain;

import jakarta.annotation.Nullable;

public record VerifyOtpResult(
        @Nullable MatrixSession session,
        @Nullable String signupToken,
        @Nullable String pinChallengeToken,
        boolean isNewUser,
        boolean isPinRequired) {

    public static VerifyOtpResult existingUser(MatrixSession session) {
        return new VerifyOtpResult(session, null, null, false, false);
    }

    public static VerifyOtpResult newUser(String signupToken) {
        return new VerifyOtpResult(null, signupToken, null, true, false);
    }

    public static VerifyOtpResult pinRequired(String pinChallengeToken) {
        return new VerifyOtpResult(null, null, pinChallengeToken, false, true);
    }
}
