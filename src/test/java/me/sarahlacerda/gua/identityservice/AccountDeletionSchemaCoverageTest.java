package me.sarahlacerda.gua.identityservice;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import me.sarahlacerda.gua.identityservice.service.account.AccountDeletionService;

/**
 * Every table that can hold a row about one account is either purged by account deletion or listed as
 * kept, with the reason. Applies the real migrations to Postgres and reads the column catalogue, so a
 * migration that adds such a table fails here until somebody decides which it is.
 *
 * <p>Listing a table as purged is a claim; {@code AccountDeletionServiceIntegrationTest} holds it to it
 * by seeding a row in every purged table and checking that the deletion leaves none.
 */
@Testcontainers
class AccountDeletionSchemaCoverageTest {

    /** Columns that tie a row to an account, by user id, internal number, passkey owner, phone or name. */
    private static final List<String> ACCOUNT_COLUMNS = List.of(
            "user_id", "account_id", "account_principal", "phone_digest", "username");

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
            .withDatabaseName("coverage")
            .withUsername("coverage")
            .withPassword("coverage");

    @Test
    void everyTableHoldingAccountDataIsPurgedOrKeptWithAReason() {
        Set<String> accountTables = accountTables();
        Set<String> handled = new TreeSet<>(AccountDeletionService.PURGED_TABLES);
        handled.addAll(AccountDeletionService.KEPT_TABLES.keySet());

        assertThat(accountTables).as("tables with an account column").isNotEmpty();
        assertThat(accountTables)
                .as("each table must be in AccountDeletionService.PURGED_TABLES or KEPT_TABLES")
                .isSubsetOf(handled);
        assertThat(handled)
                .as("AccountDeletionService names a table that holds no account column or does not exist")
                .isSubsetOf(accountTables);
    }

    @Test
    void noTableIsBothPurgedAndKeptAndEveryKeptTableSaysWhy() {
        Set<String> both = new HashSet<>(AccountDeletionService.PURGED_TABLES);
        both.retainAll(AccountDeletionService.KEPT_TABLES.keySet());

        assertThat(both).isEmpty();
        assertThat(AccountDeletionService.KEPT_TABLES.values()).allMatch(reason -> reason != null && !reason.isBlank());
    }

    private static Set<String> accountTables() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setUrl(postgres.getJdbcUrl());
        dataSource.setUsername(postgres.getUsername());
        dataSource.setPassword(postgres.getPassword());
        Flyway.configure()
                .dataSource(dataSource)
                .locations("classpath:db/migration")
                .load()
                .migrate();

        String placeholders = String.join(",", ACCOUNT_COLUMNS.stream().map(column -> "?").toList());
        return new TreeSet<>(new JdbcTemplate(dataSource).queryForList("""
                SELECT DISTINCT table_name FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name <> 'flyway_schema_history'
                  AND column_name IN (%s)
                """.formatted(placeholders), String.class, ACCOUNT_COLUMNS.toArray()));
    }
}
