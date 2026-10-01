package me.sarahlacerda.gua.identityservice.service.placement;

import java.util.List;

import lombok.RequiredArgsConstructor;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

// No phone column is selected.
// A phone change can leave several directory rows briefly, so the most recently updated one is read.
@Component
@RequiredArgsConstructor
public class PlacementAccountScanner {

    /** A scalar subquery, not a lateral join, so the embedded test database and Postgres agree. */
    private static final String NEXT_BATCH = """
            SELECT g.account_id,
                   g.user_id,
                   g.origin,
                   (SELECT e.homeserver_id
                      FROM directory_entries e
                     WHERE e.user_id = g.user_id
                     ORDER BY e.updated_at DESC, e.id DESC
                     LIMIT 1) AS homeserver_id
              FROM account_genesis g
             WHERE g.state = 'ATTACHED'
               AND g.user_id IS NOT NULL
               AND g.user_id > ?
             ORDER BY g.user_id
             LIMIT ?
            """;

    private static final String HEAL_DIRECTORY = """
            UPDATE directory_entries
               SET homeserver_id = ?, updated_at = CURRENT_TIMESTAMP
             WHERE user_id = ?
            """;

    private final JdbcTemplate jdbcTemplate;

    public record AccountRow(String accountId, String userId, String origin, String directoryHomeserverId) {
    }

    @Transactional(readOnly = true)
    public List<AccountRow> nextBatch(String afterUserId, int limit) {
        return jdbcTemplate.query(NEXT_BATCH,
                (rs, rowNum) -> new AccountRow(rs.getString("account_id"), rs.getString("user_id"),
                        rs.getString("origin"), rs.getString("homeserver_id")),
                afterUserId == null ? "" : afterUserId, limit);
    }

    /** Writes this deployment's registry id, not the roster id. */
    @Transactional
    public int healDirectoryHomeserver(String userId, String registryHomeserverId) {
        return jdbcTemplate.update(HEAL_DIRECTORY, registryHomeserverId, userId);
    }
}
