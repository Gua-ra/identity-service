package me.sarahlacerda.gua.identityservice.service;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.exception.InvalidUsernameException;

/**
 * Single source of truth for Gua username (Matrix localpart) rules: 3-30
 * characters of lowercase letters, digits, dot, underscore, or dash, excluding a
 * reserved set. Shared by the legacy signup flow and the interactive OIDC login
 * flow so both validate handles identically.
 */
@Component
public class UsernamePolicy {

    private static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-z0-9._-]{3,30}$");
    private static final Pattern ALL_NUMERIC_PATTERN = Pattern.compile("^[0-9]+$");
    private static final Set<String> RESERVED_USERNAMES = Set.of(
            "admin", "administrator", "root", "system", "gua", "guaa", "support", "help",
            "moderator", "matrix", "synapse", "server", "official", "staff");

    /**
     * Normalizes (trim + lowercase) and validates a requested username.
     *
     * @return the normalized localpart
     * @throws InvalidUsernameException when the username is missing, malformed, or reserved
     */
    public String normalizeAndValidate(String rawUsername) {
        if (!StringUtils.hasText(rawUsername)) {
            throw new InvalidUsernameException("Username is required");
        }
        String normalized = rawUsername.trim().toLowerCase(Locale.ROOT);
        if (!USERNAME_PATTERN.matcher(normalized).matches()) {
            throw new InvalidUsernameException(
                    "Username must be 3-30 characters: lowercase letters, digits, dot, underscore, or dash");
        }
        // MAS rejects all-numeric usernames (register.rego "username-all-numeric"):
        // the localpart must contain at least one non-numeric character. Enforce the
        // same rule here so we fail fast with a friendly message instead of letting
        // the upstream MAS policy check reject the provisioning request.
        if (ALL_NUMERIC_PATTERN.matcher(normalized).matches()) {
            throw new InvalidUsernameException("Username must contain at least one non-numeric character");
        }
        if (RESERVED_USERNAMES.contains(normalized)) {
            throw new InvalidUsernameException("That username is reserved");
        }
        return normalized;
    }
}
