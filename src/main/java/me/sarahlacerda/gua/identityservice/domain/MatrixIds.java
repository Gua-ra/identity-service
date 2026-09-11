package me.sarahlacerda.gua.identityservice.domain;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Strict parsing of Matrix user ids ({@code @localpart:server}).
 *
 * <p>This is the only code in the service that reads a localpart out of a user id, and
 * it accepts nothing but a well-formed Matrix user id. It is not where an existing
 * account's MAS localpart comes from: that is the username stored in the directory,
 * chosen by {@link me.sarahlacerda.gua.identityservice.service.AccountLocalpartResolver}
 * (ADM-001 S6). The resolver calls this parser only as its fallback for rows that have
 * no stored username.
 */
public final class MatrixIds {

    private static final Pattern MATRIX_USER_ID = Pattern.compile("^@([^:]+):(.+)$");

    private MatrixIds() {
    }

    /** True when {@code value} has the shape {@code @localpart:server}. */
    public static boolean isMatrixUserId(String value) {
        return value != null && MATRIX_USER_ID.matcher(value).matches();
    }

    /**
     * Returns the localpart of a Matrix user id, e.g. {@code @alice:example.org -> alice}.
     *
     * @throws IllegalArgumentException when {@code userId} is not a Matrix user id; the
     *                                  message never echoes the value
     */
    public static String localpartOf(String userId) {
        Matcher matcher = userId == null ? null : MATRIX_USER_ID.matcher(userId);
        if (matcher == null || !matcher.matches()) {
            throw new IllegalArgumentException("Not a Matrix user id (expected @localpart:server)");
        }
        return matcher.group(1);
    }
}
