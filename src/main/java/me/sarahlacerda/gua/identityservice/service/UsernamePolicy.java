package me.sarahlacerda.gua.identityservice.service;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.exception.InvalidUsernameException;

@Component
public class UsernamePolicy {

    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-z0-9._-]{3,30}$");
    private static final Pattern ALL_NUMERIC_PATTERN = Pattern.compile("^[0-9]+$");
    private static final Set<String> RESERVED_USERNAMES = Set.of(
            "admin", "administrator", "root", "system", "gua", "guaa", "support", "help",
            "moderator", "matrix", "synapse", "server", "official", "staff");

    public String normalizeAndValidate(String rawUsername) {
        if (!StringUtils.hasText(rawUsername)) {
            throw new InvalidUsernameException("Username is required");
        }
        String normalized = rawUsername.trim().toLowerCase(Locale.ROOT);
        if (!USERNAME_PATTERN.matcher(normalized).matches()) {
            throw new InvalidUsernameException(
                    "Username must be 3-30 characters: lowercase letters, digits, dot, underscore, or dash");
        }
        // MAS rejects all-numeric usernames (register.rego username-all-numeric).
        if (ALL_NUMERIC_PATTERN.matcher(normalized).matches()) {
            throw new InvalidUsernameException("Username must contain at least one non-numeric character");
        }
        if (RESERVED_USERNAMES.contains(normalized)) {
            throw new InvalidUsernameException("That username is reserved");
        }
        return normalized;
    }

    /** Format only, without the reserved-name and all-numeric rules: existing accounts may predate them. */
    public static boolean hasValidFormat(String localpart) {
        return localpart != null && USERNAME_PATTERN.matcher(localpart).matches();
    }
}
