package me.sarahlacerda.gua.identityservice.domain;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** The only code that reads a localpart out of a user id. */
public final class MatrixIds {

    private static final Pattern MATRIX_USER_ID = Pattern.compile("^@([^:]+):(.+)$");

    private MatrixIds() {
    }

    public static boolean isMatrixUserId(String value) {
        return value != null && MATRIX_USER_ID.matcher(value).matches();
    }

    /** The exception message never echoes the value. */
    public static String localpartOf(String userId) {
        Matcher matcher = userId == null ? null : MATRIX_USER_ID.matcher(userId);
        if (matcher == null || !matcher.matches()) {
            throw new IllegalArgumentException("Not a Matrix user id (expected @localpart:server)");
        }
        return matcher.group(1);
    }
}
