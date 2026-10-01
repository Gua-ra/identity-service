package me.sarahlacerda.gua.identityservice.service.placement;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;

import static org.assertj.core.api.Assertions.assertThat;

class MasSqlLinkReaderTest {

    private static final String JDBC_URL = "jdbc:h2:mem:mas-links;DB_CLOSE_DELAY=-1;MODE=PostgreSQL";
    private static final String PROVIDER = "01HGUAIDENTITYUPSTREAM0000";
    private static final String PHONE_IN_THE_PHONE_COLUMN = "+15550009999";

    private IdentityServiceProperties properties;
    private MasSqlLinkReader reader;

    @BeforeEach
    void setUp() throws Exception {
        try (Connection connection = DriverManager.getConnection(JDBC_URL);
                Statement statement = connection.createStatement()) {
            statement.execute("DROP ALL OBJECTS");
            statement.execute("""
                    CREATE TABLE users (user_id VARCHAR(64) PRIMARY KEY, username VARCHAR(64))
                    """);
            statement.execute("""
                    CREATE TABLE upstream_oauth_links (
                        upstream_oauth_link_id VARCHAR(64) PRIMARY KEY,
                        upstream_oauth_provider_id VARCHAR(64),
                        user_id VARCHAR(64),
                        subject VARCHAR(255),
                        human_account_name VARCHAR(64))
                    """);
            statement.execute("""
                    CREATE TABLE upstream_oauth_providers (
                        upstream_oauth_provider_id VARCHAR(64) PRIMARY KEY,
                        claims_imports VARCHAR(1024))
                    """);
            statement.execute("INSERT INTO users VALUES ('u1', 'alice')");
            statement.execute("INSERT INTO upstream_oauth_links VALUES "
                    + "('l1', '" + PROVIDER + "', 'u1', '@alice:example.test', '"
                    + PHONE_IN_THE_PHONE_COLUMN + "')");
            statement.execute("INSERT INTO upstream_oauth_links VALUES "
                    + "('l2', '" + PROVIDER + "', NULL, '@bob:example.test', NULL)");
        }

        properties = new IdentityServiceProperties();
        properties.getPlacement().getMas().getSql().setEnabled(true);
        HomeserverConfig homeserver = PlacementTestFixtures.homeserver(PlacementTestFixtures.LOCAL_ID,
                PlacementTestFixtures.DOMAIN, PlacementTestFixtures.FEDERATION_ID, "");
        homeserver.getMas().setUpstreamProviderId(PROVIDER);
        homeserver.getMas().setReadOnlyJdbcUrl(JDBC_URL);
        properties.getRouting().getHomeservers().add(homeserver);

        reader = new MasSqlLinkReader(properties, new ObjectMapper(),
                (url, username, password) -> DriverManager.getConnection(url));
    }

    @Test
    void aLinkIsReadWithItsMasUsername() {
        List<MasLink> links = reader.linksFor("@alice:example.test");

        assertThat(links).hasSize(1);
        assertThat(links.get(0).federationId()).isEqualTo(PlacementTestFixtures.FEDERATION_ID);
        assertThat(links.get(0).subject()).isEqualTo("@alice:example.test");
        assertThat(links.get(0).masUsername()).isEqualTo("alice");
    }

    @Test
    void aHomeserverWithNoExplicitFederationIdIsReadThroughTheAliasMap() {
        IdentityServiceProperties aliased = new IdentityServiceProperties();
        aliased.getPlacement().getMas().getSql().setEnabled(true);
        aliased.getPlacement().getFederationIdAliases()
                .put(PlacementTestFixtures.LOCAL_ID, PlacementTestFixtures.FEDERATION_ID);
        HomeserverConfig homeserver = PlacementTestFixtures.homeserverWithoutFederationId(
                PlacementTestFixtures.LOCAL_ID, PlacementTestFixtures.DOMAIN, "");
        homeserver.getMas().setUpstreamProviderId(PROVIDER);
        homeserver.getMas().setReadOnlyJdbcUrl(JDBC_URL);
        aliased.getRouting().getHomeservers().add(homeserver);

        MasSqlLinkReader aliasReader = new MasSqlLinkReader(aliased, new ObjectMapper(),
                (url, username, password) -> DriverManager.getConnection(url));

        assertThat(aliasReader.linksFor("@alice:example.test").get(0).federationId())
                .isEqualTo(PlacementTestFixtures.FEDERATION_ID);
    }

    @Test
    void theColumnHoldingAPhoneNumberIsNeverRead() {
        List<MasLink> links = reader.linksFor("@alice:example.test");

        assertThat(links.toString()).doesNotContain(PHONE_IN_THE_PHONE_COLUMN);
        assertThat(links.get(0).masUsername()).isNotEqualTo(PHONE_IN_THE_PHONE_COLUMN);
    }

    @Test
    void theReaderSourceNeitherNamesThePhoneColumnNorSelectsAWildcard() throws Exception {
        Path source = Path.of("src", "main", "java", "me", "sarahlacerda", "gua", "identityservice",
                "service", "placement", "MasSqlLinkReader.java");
        assertThat(source).isRegularFile();
        String code = Files.readString(source);

        // The class comment names the column once. No SQL line may.
        List<String> sqlLines = code.lines()
                .map(String::trim)
                .filter(line -> line.toUpperCase(java.util.Locale.ROOT).startsWith("SELECT")
                        || line.toUpperCase(java.util.Locale.ROOT).startsWith("FROM")
                        || line.toUpperCase(java.util.Locale.ROOT).startsWith("LEFT JOIN")
                        || line.toUpperCase(java.util.Locale.ROOT).startsWith("WHERE")
                        || line.toUpperCase(java.util.Locale.ROOT).startsWith("AND"))
                .toList();
        assertThat(sqlLines).isNotEmpty();
        assertThat(sqlLines).noneMatch(line -> line.contains("human_account_name"));
        assertThat(sqlLines).noneMatch(line -> line.contains("SELECT *"));
    }

    @Test
    void anUnfinishedLoginIsNotEvidenceOfPlacement() {
        assertThat(reader.linksFor("@bob:example.test")).isEmpty();
    }

    @Test
    void theEffectiveOnConflictPolicyIsReadWithTheMasDefaultApplied() throws Exception {
        assertThat(reader.localpartOnConflictByHomeserver()).isEmpty();

        insertClaimsImports("{\"localpart\":{\"action\":\"require\",\"on_conflict\":\"add\"}}");
        assertThat(reader.localpartOnConflictByHomeserver())
                .isEqualTo(Map.of(PlacementTestFixtures.FEDERATION_ID, "add"));

        updateClaimsImports("{\"localpart\":{\"action\":\"require\"}}");
        assertThat(reader.localpartOnConflictByHomeserver())
                .isEqualTo(Map.of(PlacementTestFixtures.FEDERATION_ID, "fail"));
    }

    @Test
    void theReaderIsUnconfiguredUntilTheFlagAndAJdbcUrlAreBothSet() {
        assertThat(reader.isConfigured()).isTrue();

        properties.getPlacement().getMas().getSql().setEnabled(false);
        assertThat(reader.isConfigured()).isFalse();

        properties.getPlacement().getMas().getSql().setEnabled(true);
        properties.getRouting().getHomeservers().get(0).getMas().setReadOnlyJdbcUrl("");
        assertThat(reader.isConfigured()).isFalse();
    }

    private void insertClaimsImports(String json) throws Exception {
        try (Connection connection = DriverManager.getConnection(JDBC_URL);
                Statement statement = connection.createStatement()) {
            statement.execute("INSERT INTO upstream_oauth_providers VALUES ('" + PROVIDER + "', '" + json + "')");
        }
    }

    private void updateClaimsImports(String json) throws Exception {
        try (Connection connection = DriverManager.getConnection(JDBC_URL);
                Statement statement = connection.createStatement()) {
            statement.execute("UPDATE upstream_oauth_providers SET claims_imports = '" + json + "'");
        }
    }
}
