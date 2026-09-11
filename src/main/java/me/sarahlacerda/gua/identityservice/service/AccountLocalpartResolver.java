package me.sarahlacerda.gua.identityservice.service;

import java.util.List;

import lombok.RequiredArgsConstructor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.domain.MatrixIds;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;

/**
 * Chooses the localpart an existing account presents as the {@code preferred_username}
 * claim, which MAS imports as the Matrix localpart on a first delegated login
 * (ADM-001 S6).
 *
 * <p>The source is the username stored in the directory: the handle reserved at signup
 * under the directory's case-insensitive unique index, which no code path changes once
 * stored (a phone change carries it forward). It is read, never derived from the user
 * id, so re-keying {@code user_id} cannot change what an account presents to MAS.
 *
 * <p>Rows without a stored username (legacy native signups, rows healed from the
 * homeserver phone binding) fall back to the localpart of a well-formed Matrix user id,
 * via {@link MatrixIds}. That value is unique on its own homeserver; it is refused when
 * another account in this directory holds it as its stored username, and it is never
 * produced from a user id that is not a Matrix user id.
 *
 * <p>Every candidate must also match the username format
 * ({@link UsernamePolicy#hasValidFormat}), which is lowercase because MAS matches
 * localparts case-insensitively. Anything that fails is refused with
 * {@code account_identity_inconsistent} instead of being sent: with the MAS claims
 * import set to {@code on_conflict: add}, a localpart shared by two accounts links the
 * second account onto the first account's MAS user.
 */
@Component
@RequiredArgsConstructor
public class AccountLocalpartResolver {

    public static final String INCONSISTENT_CODE = "account_identity_inconsistent";

    private static final Logger log = LoggerFactory.getLogger(AccountLocalpartResolver.class);

    private final DirectoryService directoryService;

    /**
     * @param userId the account's Matrix user id (the OIDC {@code sub})
     * @param rows   the account's directory rows the caller already loaded; may be empty
     * @return the localpart to emit as {@code preferred_username}
     * @throws LoginFlowException 500 {@code account_identity_inconsistent} when no
     *                            per-account localpart can be established
     */
    public String forExistingAccount(String userId, List<DirectoryEntry> rows) {
        if (!StringUtils.hasText(userId)) {
            throw inconsistent(null, "missing user id");
        }
        if (rows.stream().anyMatch(row -> !userId.equals(row.getUserId()))) {
            throw inconsistent(userId, "a directory row passed in belongs to another account");
        }

        List<String> stored = rows.stream()
                .map(DirectoryEntry::getUsername)
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .toList();
        if (stored.size() > 1) {
            throw inconsistent(userId, "the account has more than one stored username");
        }

        String derived = MatrixIds.isMatrixUserId(userId) ? MatrixIds.localpartOf(userId) : null;
        String candidate;
        if (!stored.isEmpty()) {
            candidate = stored.get(0);
            if (derived != null && !candidate.equals(derived)) {
                log.warn("Stored username differs from the Matrix user id localpart for {}; emitting the stored username",
                        userId);
            }
        } else if (derived != null) {
            candidate = derived;
        } else {
            throw inconsistent(userId, "no stored username and the user id is not a Matrix user id");
        }

        if (!UsernamePolicy.hasValidFormat(candidate)) {
            throw inconsistent(userId, "the localpart does not match the username format");
        }
        if (directoryService.resolveByUsername(candidate)
                .filter(holder -> !userId.equals(holder.getUserId()))
                .isPresent()) {
            throw inconsistent(userId, "the localpart is another account's stored username");
        }
        return candidate;
    }

    private static LoginFlowException inconsistent(String userId, String reason) {
        log.warn("Refusing to emit a localpart for account {}: {}", userId, reason);
        return new LoginFlowException(HttpStatus.INTERNAL_SERVER_ERROR, INCONSISTENT_CODE,
                "This account cannot sign in right now. Please contact support.");
    }
}
