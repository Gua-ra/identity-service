package me.sarahlacerda.gua.identityservice.service.account;

import java.util.List;

import lombok.RequiredArgsConstructor;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Reads the set of accounts this deployment knows about, for the bootstrap backfill and the
 * missing-genesis gauge.
 *
 * <p>An account is any user id that appears in the directory or in the security tables. Both are needed:
 * a directory row exists from signup, an {@code identity_users} row from the first successful login, and
 * neither is guaranteed to exist without the other.
 */
@Component
@RequiredArgsConstructor
public class AccountScanner {

    /**
     * Keyset pagination rather than OFFSET, so the backfill is resumable: it continues from the last
     * user id it saw, and rows inserted while it runs are picked up rather than shifting the window.
     */
    private static final String NEXT_BATCH = """
            SELECT user_id FROM (
                SELECT user_id FROM directory_entries
                UNION
                SELECT user_id FROM identity_users
            ) accounts
            WHERE user_id > ?
            ORDER BY user_id
            LIMIT ?
            """;

    private static final String COUNT_WITHOUT_GENESIS = """
            SELECT count(*) FROM (
                SELECT user_id FROM directory_entries
                UNION
                SELECT user_id FROM identity_users
            ) accounts
            WHERE NOT EXISTS (
                SELECT 1 FROM account_genesis g WHERE g.user_id = accounts.user_id
            )
            """;

    private final JdbcTemplate jdbcTemplate;

    /** The next batch of account user ids in ascending order, after {@code afterUserId}. */
    @Transactional(readOnly = true)
    public List<String> nextBatch(String afterUserId, int limit) {
        return jdbcTemplate.queryForList(NEXT_BATCH, String.class, afterUserId == null ? "" : afterUserId, limit);
    }

    /** How many accounts still hold no genesis row. Alerted on when it stays above zero. */
    @Transactional(readOnly = true)
    public long countAccountsWithoutGenesis() {
        Long count = jdbcTemplate.queryForObject(COUNT_WITHOUT_GENESIS, Long.class);
        return count == null ? 0L : count;
    }
}
