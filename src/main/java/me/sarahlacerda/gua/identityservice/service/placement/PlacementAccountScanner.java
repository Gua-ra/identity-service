// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.util.List;

import lombok.RequiredArgsConstructor;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Reads the accounts the shadow comparison walks: an accountId, the account it is attached to, its
 * origin, and this service's local routing choice for it.
 *
 * <p><b>No phone column is selected here.</b> {@code directory_entries} holds a phone digest and a
 * masked phone, and neither is in the statement below or needed by anything downstream. The comparison
 * works on accountIds, Matrix user ids and homeserver ids only.
 *
 * <p>Multiple directory rows exist for one account transiently while a phone change is in flight, so
 * the routing choice is read with a scalar subquery that takes the most recently updated row. Counting
 * an account twice, or reading the row that is about to be deleted, would produce findings that are
 * artefacts of the scan.
 *
 * <p>Keyset pagination rather than OFFSET, so a long run is resumable and rows inserted while it runs
 * do not shift the window.
 */
@Component
@RequiredArgsConstructor
public class PlacementAccountScanner {

    /**
     * Portable on purpose: a scalar subquery with {@code ORDER BY ... LIMIT 1} rather than a lateral
     * join, so the embedded engine the unit profile uses and the Postgres production runs on agree.
     */
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

    /**
     * One account as the comparison sees it.
     *
     * @param accountId            the permanent accountId
     * @param userId               the account's Matrix user id
     * @param origin               {@code GENESIS} or {@code BOOTSTRAP}, the audit marker the record's
     *                             origin byte is taken from
     * @param directoryHomeserverId this service's local routing choice, null for rows written before
     *                             routing existed
     */
    public record AccountRow(String accountId, String userId, String origin, String directoryHomeserverId) {
    }

    /** The next batch of accounts in user-id order, after {@code afterUserId}. */
    @Transactional(readOnly = true)
    public List<AccountRow> nextBatch(String afterUserId, int limit) {
        return jdbcTemplate.query(NEXT_BATCH,
                (rs, rowNum) -> new AccountRow(rs.getString("account_id"), rs.getString("user_id"),
                        rs.getString("origin"), rs.getString("homeserver_id")),
                afterUserId == null ? "" : afterUserId, limit);
    }

    /**
     * Writes the local routing choice back from the evidence. Only reached behind
     * {@code identity.placement.shadow.heal-directory}, which is off by default.
     *
     * @param registryHomeserverId this deployment's own registry id, not the roster id: the directory
     *                             column has always held the local namespace and this does not change it
     * @return rows updated
     */
    @Transactional
    public int healDirectoryHomeserver(String userId, String registryHomeserverId) {
        return jdbcTemplate.update(HEAL_DIRECTORY, registryHomeserverId, userId);
    }
}
