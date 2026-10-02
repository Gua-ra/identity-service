package me.sarahlacerda.gua.identityservice.domain;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Strict parsing of Matrix user ids ({@code @localpart:server}).
 *
 * <p>The only code that reads a localpart out of a user id. An existing account's MAS localpart
 * comes from the directory username instead (see
 * {@link me.sarahlacerda.gua.identityservice.service.AccountLocalpartResolver}), which calls this
 * parser only as its fallback for rows with no stored username.
 */
public final class MatrixIds {

    private static final Pattern MATRIX_USER_ID = Pattern.compile("^@([^:]+):(.+)$");

    private MatrixIds() {
    }

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
