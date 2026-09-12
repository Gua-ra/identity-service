package me.sarahlacerda.gua.identityservice.repository;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord.Origin;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord.State;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The genesis table against a real database engine.
 *
 * <p>The compare-and-set attach is the point of this class: it is what makes two sessions racing on one
 * handle resolve to a single attach, and a mocked repository cannot show that the SQL actually says so.
 *
 * <p>The schema comes from the entity mapping rather than from Flyway, because the migrations are
 * Postgres-only and will not run on an embedded database (V5 alone adds two columns in one ALTER TABLE
 * and indexes an expression). That the mapping and the migration agree is a separate question, and it
 * is the one {@code SchemaParityTest} answers on Postgres.
 */
@DataJpaTest(properties = {
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.sql.init.mode=never"
})
class AccountGenesisRepositoryTest {

    private static final String HANDLE_HASH = "a".repeat(64);

    @Autowired
    private AccountGenesisRepository repository;

    private AccountGenesisRecord pending(String accountId, String handleHash, Instant expiresAt) {
        return AccountGenesisRecord.pendingGenesis(accountId, (short) 1, (short) 1, "Z2VuZXNpcw",
                "a2V5", handleHash, expiresAt);
    }

    @Test
    void aPendingRegistrationIsFoundByItsHandleHash() {
        repository.saveAndFlush(pending("ga1pending", HANDLE_HASH, Instant.now().plusSeconds(600)));

        assertThat(repository.findByAttachHandleHash(HANDLE_HASH))
                .get()
                .extracting(AccountGenesisRecord::getAccountId)
                .isEqualTo("ga1pending");
        assertThat(repository.findByAttachHandleHash("b".repeat(64))).isEmpty();
    }

    @Test
    void theAttachCompareAndSetSucceedsExactlyOnce() {
        repository.saveAndFlush(pending("ga1racer", HANDLE_HASH, Instant.now().plusSeconds(600)));

        int first = repository.attach("ga1racer", HANDLE_HASH, "@alice:example.org", Instant.now(),
                State.PENDING, State.ATTACHED);
        int second = repository.attach("ga1racer", HANDLE_HASH, "@mallory:example.org", Instant.now(),
                State.PENDING, State.ATTACHED);

        assertThat(first).isEqualTo(1);
        assertThat(second).isZero();

        AccountGenesisRecord row = repository.findById("ga1racer").orElseThrow();
        assertThat(row.getState()).isEqualTo(State.ATTACHED);
        assertThat(row.getUserId()).isEqualTo("@alice:example.org");
        assertThat(row.getAttachHandleHash()).isNull();
        assertThat(row.getAttachedAt()).isNotNull();
    }

    @Test
    void theAttachRefusesAHandleThatDoesNotMatchTheRow() {
        repository.saveAndFlush(pending("ga1mismatch", HANDLE_HASH, Instant.now().plusSeconds(600)));

        int updated = repository.attach("ga1mismatch", "c".repeat(64), "@alice:example.org", Instant.now(),
                State.PENDING, State.ATTACHED);

        assertThat(updated).isZero();
        assertThat(repository.findById("ga1mismatch").orElseThrow().getState()).isEqualTo(State.PENDING);
    }

    @Test
    void oneAccountCannotHoldTwoGenesisRows() {
        repository.saveAndFlush(AccountGenesisRecord.attachedBootstrap("ga1first", "@alice:example.org",
                (short) 1, (short) 0, "Ym9vdA", Instant.now()));

        assertThatThrownBy(() -> repository.saveAndFlush(AccountGenesisRecord.attachedBootstrap("ga1second",
                "@alice:example.org", (short) 1, (short) 0, "Ym9vdDI", Instant.now())))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void severalPendingRowsMayCoexistBecauseTheirUserIdIsNull() {
        repository.saveAndFlush(pending("ga1p1", "d".repeat(64), Instant.now().plusSeconds(600)));
        repository.saveAndFlush(pending("ga1p2", "e".repeat(64), Instant.now().plusSeconds(600)));

        assertThat(repository.count()).isEqualTo(2);
    }

    @Test
    void theSweepDeletesOnlyExpiredPendingRows() {
        repository.saveAndFlush(pending("ga1expired", "f".repeat(64), Instant.now().minusSeconds(1)));
        repository.saveAndFlush(pending("ga1live", "0".repeat(64), Instant.now().plusSeconds(600)));
        repository.saveAndFlush(AccountGenesisRecord.attachedBootstrap("ga1attached", "@bob:example.org",
                (short) 1, (short) 0, "Ym9vdA", Instant.now()));

        int deleted = repository.deleteExpiredPending(State.PENDING, Instant.now());

        assertThat(deleted).isEqualTo(1);
        assertThat(repository.findById("ga1expired")).isEmpty();
        assertThat(repository.findById("ga1live")).isPresent();
        assertThat(repository.findById("ga1attached")).isPresent();
    }

    @Test
    void theOriginSplitIsCountable() {
        repository.saveAndFlush(AccountGenesisRecord.attachedBootstrap("ga1b1", "@a:example.org",
                (short) 1, (short) 0, "Ym9vdA", Instant.now()));
        repository.saveAndFlush(AccountGenesisRecord.attachedBootstrap("ga1b2", "@b:example.org",
                (short) 1, (short) 0, "Ym9vdA", Instant.now()));
        repository.saveAndFlush(pending("ga1g1", "1".repeat(64), Instant.now().plusSeconds(600)));

        assertThat(repository.countByOrigin(Origin.BOOTSTRAP)).isEqualTo(2);
        assertThat(repository.countByOrigin(Origin.GENESIS)).isEqualTo(1);
    }

    @Test
    void theBackfillCanAskWhichAccountsAlreadyHoldARow() {
        repository.saveAndFlush(AccountGenesisRecord.attachedBootstrap("ga1known", "@known:example.org",
                (short) 1, (short) 0, "Ym9vdA", Instant.now()));

        List<String> existing = repository.findExistingUserIds(
                List.of("@known:example.org", "@missing:example.org"));

        assertThat(existing).containsExactly("@known:example.org");
    }

    @Test
    void anAccountsGenesisIsFoundByItsUserId() {
        repository.saveAndFlush(AccountGenesisRecord.attachedBootstrap("ga1byuser", "@alice:example.org",
                (short) 1, (short) 0, "Ym9vdA", Instant.now()));

        assertThat(repository.findByUserId("@alice:example.org")).isPresent();
        assertThat(repository.existsByUserId("@alice:example.org")).isTrue();
        assertThat(repository.existsByUserId("@nobody:example.org")).isFalse();
    }
}
