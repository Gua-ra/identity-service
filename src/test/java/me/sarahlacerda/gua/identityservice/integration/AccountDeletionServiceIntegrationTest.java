package me.sarahlacerda.gua.identityservice.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.service.account.AccountDeletionService;
import me.sarahlacerda.gua.identityservice.service.account.AccountDeletionService.Purge;
import me.sarahlacerda.gua.identityservice.service.account.AccountGenesisService;
import me.sarahlacerda.gua.identityservice.service.security.PasskeyPrincipals;

/**
 * Account deletion through the proxied bean against Postgres and Redis, the way the endpoint calls it.
 *
 * <p>The test opens no transaction of its own, so each deletion commits or rolls back exactly as it does
 * in production. Account genesis is switched off here, which is the case where the tombstone must still
 * be written.
 */
@SpringBootTest
@Testcontainers
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AccountDeletionServiceIntegrationTest {

    /**
     * How to count one account's rows in each purged table. Kept equal to
     * {@link AccountDeletionService#PURGED_TABLES}, so a table added to the purge needs a seed and a check
     * here before this class passes.
     */
    private static final Map<String, String> ROWS_OF_ACCOUNT = Map.of(
            "directory_entries", "user_id = :userId",
            "identity_users", "user_id = :userId",
            "passkey_credentials", "user_id = :userId OR account_principal = :principal",
            "trusted_devices", "user_id = :userId");

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
            .withDatabaseName("identity")
            .withUsername("identity")
            .withPassword("identity");

    @Container
    static GenericContainer<?> redisContainer = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.data.redis.host", redisContainer::getHost);
        registry.add("spring.data.redis.port", () -> redisContainer.getMappedPort(6379).toString());

        registry.add("identity.matrix.admin-api-base-url", () -> "http://localhost:1");
        registry.add("identity.matrix.client-api-base-url", () -> "http://localhost:1");
        registry.add("identity.matrix.homeserver-domain", () -> "example.com");
        registry.add("identity.matrix.admin-access-token", () -> "test-admin-token");
        registry.add("identity.directory.pepper", () -> "test-pepper");
        registry.add("identity.sms.twilio.enabled", () -> "false");
        registry.add("identity.rate-limits.enabled", () -> "false");
        registry.add("identity.genesis.enabled", () -> "false");
        registry.add("identity.genesis.bootstrap-backfill.enabled", () -> "false");
        registry.add("oidc.issuer", () -> "http://localhost");
    }

    @Autowired
    AccountDeletionService deletionService;

    @Autowired
    AccountGenesisService genesisService;

    @Autowired
    PasskeyPrincipals passkeyPrincipals;

    @Autowired
    JdbcTemplate jdbc;

    @Autowired
    NamedParameterJdbcTemplate namedJdbc;

    @Autowired
    StringRedisTemplate redis;

    @Test
    void deletingAnAccountRemovesEveryRowOfItAndLeavesAnotherAccountAlone() {
        assertThat(ROWS_OF_ACCOUNT.keySet()).isEqualTo(AccountDeletionService.PURGED_TABLES);
        String alice = newUserId();
        String bob = newUserId();
        String alicePrincipal = seedAccount(alice);
        String bobPrincipal = seedAccount(bob);
        seedRedisState(alice);
        seedRedisState(bob);
        Map<String, Integer> bobBefore = rowsOf(bob, bobPrincipal);
        assertThat(rowsOf(alice, alicePrincipal).values()).allMatch(count -> count > 0);
        String aliceAccountNumber = genesisColumn(alice, "account_id");

        Purge purge = deletionService.delete(alice);

        assertThat(purge).isEqualTo(new Purge(2, 1, 3, 2));
        assertThat(rowsOf(alice, alicePrincipal).values()).allMatch(count -> count == 0);
        assertThat(rowsOf(bob, bobPrincipal)).isEqualTo(bobBefore);

        assertThat(genesisColumn(alice, "state")).isEqualTo("DELETED");
        assertThat(genesisColumn(alice, "account_id")).isEqualTo(aliceAccountNumber);
        assertThat(genesisColumn(alice, "origin")).isEqualTo("BOOTSTRAP");
        assertThat(genesisColumn(alice, "attach_handle_hash")).isNull();
        assertThat(genesisColumn(bob, "state")).isEqualTo("ATTACHED");
        assertThat(genesisService.isDeleted(alice)).isTrue();
        assertThat(genesisService.isDeleted(bob)).isFalse();

        assertThat(redis.hasKey("reauth:phone-mismatch:" + alice)).isFalse();
        assertThat(redis.hasKey("recovery:end-other-sessions:" + alice)).isFalse();
        assertThat(redis.hasKey("reauth:phone-mismatch:" + bob)).isTrue();
        assertThat(redis.hasKey("recovery:end-other-sessions:" + bob)).isTrue();
        assertThat(redis.opsForValue().get("oidc:revoke-before:" + alice)).isNotBlank();
        assertThat(redis.getExpire("oidc:revoke-before:" + alice))
                .isPositive()
                .isLessThanOrEqualTo(Duration.ofHours(1).toSeconds());
        assertThat(redis.hasKey("oidc:revoke-before:" + bob)).isFalse();
    }

    @Test
    void aSecondDeletionChangesNothing() {
        String alice = newUserId();
        seedAccount(alice);
        deletionService.delete(alice);
        Map<String, Object> tombstone = genesisRow(alice);

        Purge repeat = deletionService.delete(alice);

        assertThat(repeat).isEqualTo(new Purge(0, 0, 0, 0));
        assertThat(genesisRow(alice)).isEqualTo(tombstone);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM account_genesis WHERE user_id = ?", Integer.class, alice))
                .isEqualTo(1);
    }

    /** The tombstone is the last write, so a failure there must take every delete before it back. */
    @Test
    void aFailureHalfwayLeavesEverythingInPlace() {
        String alice = newUserId();
        String principal = seedAccount(alice);
        seedRedisState(alice);
        Map<String, Integer> before = rowsOf(alice, principal);
        jdbc.execute("""
                CREATE OR REPLACE FUNCTION refuse_tombstone() RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'tombstone refused by the test';
                END;
                $$ LANGUAGE plpgsql
                """);
        jdbc.execute("CREATE TRIGGER refuse_tombstone BEFORE INSERT OR UPDATE ON account_genesis FOR EACH ROW "
                + "WHEN (NEW.user_id = '" + alice + "') EXECUTE FUNCTION refuse_tombstone()");
        try {
            assertThatThrownBy(() -> deletionService.delete(alice)).isInstanceOf(DataAccessException.class);
        } finally {
            jdbc.execute("DROP TRIGGER refuse_tombstone ON account_genesis");
            jdbc.execute("DROP FUNCTION refuse_tombstone()");
        }

        assertThat(rowsOf(alice, principal)).isEqualTo(before);
        assertThat(genesisColumn(alice, "state")).isEqualTo("ATTACHED");
        assertThat(redis.hasKey("oidc:revoke-before:" + alice)).isFalse();
        assertThat(redis.hasKey("reauth:phone-mismatch:" + alice)).isTrue();
        assertThat(redis.hasKey("recovery:end-other-sessions:" + alice)).isTrue();
    }

    @Test
    void theTombstoneIsWrittenForAnAccountThatHeldNoGenesisRow() {
        String carol = newUserId();
        insertDirectoryEntry(carol, "carol-" + UUID.randomUUID(), null);

        Purge purge = deletionService.delete(carol);

        assertThat(purge).isEqualTo(new Purge(1, 0, 0, 0));
        assertThat(genesisColumn(carol, "state")).isEqualTo("DELETED");
        assertThat(genesisColumn(carol, "origin")).isEqualTo("BOOTSTRAP");
        assertThat(genesisColumn(carol, "attached_at")).isNull();
        assertThat(AccountId.parse(genesisColumn(carol, "account_id")).rootClass())
                .isEqualTo(AccountId.CLASS_BOOTSTRAP);
        assertThat(genesisService.isDeleted(carol)).isTrue();
    }

    @Test
    void anAccountNeverSeenHereIsStillTombstoned() {
        String dave = newUserId();

        assertThat(deletionService.delete(dave)).isEqualTo(new Purge(0, 0, 0, 0));
        assertThat(genesisService.isDeleted(dave)).isTrue();
    }

    @Test
    void theTombstoneRefusesToBeWrittenOutsideATransaction() {
        assertThatThrownBy(() -> genesisService.markDeleted(newUserId()))
                .isInstanceOf(IllegalTransactionStateException.class);
    }

    // --- Seeding ------------------------------------------------------------------

    private static String newUserId() {
        return "@u" + UUID.randomUUID().toString().replace("-", "").substring(0, 12) + ":example.com";
    }

    /**
     * Gives the account a row in every purged table, through the attached genesis row a real account
     * holds, and returns its passkey principal. Passkeys: one from before principals existed, one under the
     * principal, and one under the principal with an older user id.
     */
    private String seedAccount(String userId) {
        String tag = UUID.randomUUID().toString();
        insertDirectoryEntry(userId, "first-" + tag, "u" + tag.replace("-", "").substring(0, 12));
        insertDirectoryEntry(userId, "second-" + tag, null);
        jdbc.update("INSERT INTO identity_users (id, user_id, pin_hash, last_login_at) VALUES (?, ?, ?, now())",
                UUID.randomUUID(), userId, "$2a$10$notarealhashnotarealhashnotarealhashnotarealhashno");
        for (String device : new String[] { "device-1", "device-2" }) {
            jdbc.update("INSERT INTO trusted_devices (id, user_id, device_id, device_name, platform, app_version, last_ip) "
                    + "VALUES (?, ?, ?, 'Phone', 'iOS', '1.0', '203.0.113.9')", UUID.randomUUID(), userId, device);
        }
        genesisService.bootstrap(userId);
        String principal = passkeyPrincipals.forUserId(userId).orElseThrow().text();
        insertPasskey(userId, null);
        insertPasskey(userId, principal);
        insertPasskey("@previous" + tag.substring(0, 8) + ":example.com", principal);
        return principal;
    }

    private void insertDirectoryEntry(String userId, String digest, String username) {
        jdbc.update("INSERT INTO directory_entries (id, phone_digest, user_id, display_name, phone_masked, username) "
                + "VALUES (?, ?, ?, 'Someone', '••••1234', ?)", UUID.randomUUID(), digest, userId,
                username);
    }

    private void insertPasskey(String userId, String principal) {
        jdbc.update("INSERT INTO passkey_credentials (id, user_id, user_handle, credential_id, public_key_cose, "
                + "account_principal) VALUES (?, ?, 'handle', ?, 'cose', ?)", UUID.randomUUID(), userId,
                UUID.randomUUID().toString(), principal);
    }

    private void seedRedisState(String userId) {
        redis.opsForValue().set("reauth:phone-mismatch:" + userId, "1", Duration.ofHours(1));
        redis.opsForValue().set("recovery:end-other-sessions:" + userId, "1", Duration.ofHours(1));
    }

    private Map<String, Integer> rowsOf(String userId, String principal) {
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("userId", userId)
                .addValue("principal", principal);
        Map<String, Integer> counts = new LinkedHashMap<>();
        ROWS_OF_ACCOUNT.forEach((table, predicate) -> counts.put(table,
                namedJdbc.queryForObject("SELECT count(*) FROM " + table + " WHERE " + predicate, params,
                        Integer.class)));
        return counts;
    }

    private String genesisColumn(String userId, String column) {
        Object value = genesisRow(userId).get(column);
        return value == null ? null : value.toString();
    }

    private Map<String, Object> genesisRow(String userId) {
        return jdbc.queryForMap("SELECT * FROM account_genesis WHERE user_id = ?", userId);
    }
}
