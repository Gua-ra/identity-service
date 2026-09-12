package me.sarahlacerda.gua.identityservice;

import java.sql.Connection;
import java.sql.Statement;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.sql.DataSource;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ScriptUtils;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The hand-mirrored schema (src/test/resources/db/schema-mirror.sql) is written by hand from the Flyway
 * migrations, which is the likeliest source of a test-versus-production divergence. This applies the
 * real migrations to one schema, the hand-written mirror to another, and compares the resulting columns.
 *
 * <p>Mirrors the test of the same name in gua-resolver, which guards the same hazard there. It runs on
 * Postgres rather than H2 because the migrations are Postgres-only: V5 adds two columns in a single
 * ALTER TABLE and indexes {@code LOWER(username)}, neither of which H2 accepts. Running the comparison
 * on the engine production uses is also the only way the answer means anything. Like the other
 * Testcontainers classes here, it needs a Docker daemon.
 */
@Testcontainers
class SchemaParityTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
            .withDatabaseName("parity")
            .withUsername("parity")
            .withPassword("parity");

    @Test
    void theHandMirroredSchemaMatchesTheFlywayMigrations() throws Exception {
        DataSource dataSource = dataSource();
        execute(dataSource, "CREATE SCHEMA migrated", "CREATE SCHEMA mirrored");

        Flyway.configure()
                .dataSource(dataSource)
                .schemas("migrated")
                .defaultSchema("migrated")
                .locations("classpath:db/migration")
                .load()
                .migrate();

        try (Connection connection = dataSource.getConnection()) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("SET search_path TO mirrored");
            }
            ScriptUtils.executeSqlScript(connection, new ClassPathResource("db/schema-mirror.sql"));
        }

        assertThat(columns(dataSource, "mirrored")).isEqualTo(columns(dataSource, "migrated"));
    }

    /**
     * Resolved through DriverManager rather than a named Driver class: the Postgres driver is a
     * runtimeOnly dependency, so it is on the test runtime classpath but not the compile one.
     */
    private static DataSource dataSource() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setUrl(postgres.getJdbcUrl());
        dataSource.setUsername(postgres.getUsername());
        dataSource.setPassword(postgres.getPassword());
        return dataSource;
    }

    private static void execute(DataSource dataSource, String... statements) throws Exception {
        try (Connection connection = dataSource.getConnection();
                Statement statement = connection.createStatement()) {
            for (String sql : statements) {
                statement.execute(sql);
            }
        }
    }

    /** table.column to type and nullability, for every table except Flyway's own bookkeeping. */
    private static Map<String, String> columns(DataSource dataSource, String schema) {
        Map<String, String> columns = new LinkedHashMap<>();
        new JdbcTemplate(dataSource).query("""
                SELECT table_name, column_name, data_type, character_maximum_length, is_nullable
                FROM information_schema.columns
                WHERE table_schema = ? AND table_name <> 'flyway_schema_history'
                ORDER BY table_name, column_name
                """, rs -> {
            columns.put(rs.getString("table_name") + "." + rs.getString("column_name"),
                    rs.getString("data_type") + "(" + rs.getString("character_maximum_length") + ") "
                            + rs.getString("is_nullable"));
        }, schema);
        return columns;
    }
}
