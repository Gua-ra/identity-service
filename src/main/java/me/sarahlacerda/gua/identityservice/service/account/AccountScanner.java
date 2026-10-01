package me.sarahlacerda.gua.identityservice.service.account;

import java.util.List;

import lombok.RequiredArgsConstructor;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

// An account is any user id in the directory or the security tables. Neither row is guaranteed to exist without
// the other.
@Component
@RequiredArgsConstructor
public class AccountScanner {

    /** Keyset pagination, so the backfill is resumable. */
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

    @Transactional(readOnly = true)
    public List<String> nextBatch(String afterUserId, int limit) {
        return jdbcTemplate.queryForList(NEXT_BATCH, String.class, afterUserId == null ? "" : afterUserId, limit);
    }

    @Transactional(readOnly = true)
    public long countAccountsWithoutGenesis() {
        Long count = jdbcTemplate.queryForObject(COUNT_WITHOUT_GENESIS, Long.class);
        return count == null ? 0L : count;
    }
}
