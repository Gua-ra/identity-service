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

// The preferred_username MAS imports as the localpart: the stored directory username, else the MXID localpart.
// Two accounts sharing a localpart would be merged in MAS, so a conflict is refused.
@Component
@RequiredArgsConstructor
public class AccountLocalpartResolver {

    public static final String INCONSISTENT_CODE = "account_identity_inconsistent";

    private static final Logger log = LoggerFactory.getLogger(AccountLocalpartResolver.class);

    private final DirectoryService directoryService;

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
