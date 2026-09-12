// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;

/**
 * The fallback MAS read path: a read-only role on each MAS database.
 *
 * <p><b>Not available on this deployment.</b> No such role exists on any MAS database. Granting it
 * means creating a login role per MAS with {@code SELECT} on exactly three tables,
 * {@code upstream_oauth_links}, {@code users} and {@code upstream_oauth_providers}, and nothing else.
 * Until then this reader reports itself unconfigured
 * ({@code identity.placement.mas.sql.enabled}).
 *
 * <p><b>The column this must never read.</b> {@code upstream_oauth_links.human_account_name} holds the
 * account's phone number in the deployed MAS configuration. It is not in any statement below, it is not
 * selected by {@code SELECT *} anywhere here, and {@code MasSqlLinkReaderTest} fails if it ever appears
 * in this file. Neither the links query nor the provider query may grow it.
 */
@Component
public class MasSqlLinkReader implements MasLinkReader {

    private static final Logger log = LoggerFactory.getLogger(MasSqlLinkReader.class);

    /**
     * Columns named one by one, never {@code SELECT *}: a wildcard here would start returning the phone
     * column the moment someone reordered the table.
     */
    private static final String LINKS_QUERY = """
            SELECT l.subject, l.user_id, u.username
              FROM upstream_oauth_links l
              LEFT JOIN users u ON u.user_id = l.user_id
             WHERE l.upstream_oauth_provider_id = ?
               AND l.subject = ?
               AND l.user_id IS NOT NULL
            """;

    private static final String CLAIMS_IMPORTS_QUERY = """
            SELECT claims_imports
              FROM upstream_oauth_providers
             WHERE upstream_oauth_provider_id = ?
            """;

    /** How a connection to one MAS database is opened. Overridable so tests need no live database. */
    @FunctionalInterface
    public interface ConnectionFactory {
        Connection open(String jdbcUrl, String username, String password) throws SQLException;
    }

    private final IdentityServiceProperties properties;
    private final ObjectMapper objectMapper;
    private final ConnectionFactory connections;
    private final FederationIds federationIds;

    @Autowired
    public MasSqlLinkReader(IdentityServiceProperties properties, ObjectMapper objectMapper,
            FederationIds federationIds) {
        this(properties, objectMapper, DriverManager::getConnection, federationIds);
    }

    public MasSqlLinkReader(IdentityServiceProperties properties, ObjectMapper objectMapper,
            ConnectionFactory connections) {
        this(properties, objectMapper, connections, new FederationIds(properties));
    }

    public MasSqlLinkReader(IdentityServiceProperties properties, ObjectMapper objectMapper,
            ConnectionFactory connections, FederationIds federationIds) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.connections = connections;
        this.federationIds = federationIds;
    }

    @Override
    public boolean isConfigured() {
        return properties.getPlacement().getMas().getSql().isEnabled() && !usableHomeservers().isEmpty();
    }

    @Override
    public String describe() {
        return "read-only SQL role on each MAS database";
    }

    private List<HomeserverConfig> usableHomeservers() {
        List<HomeserverConfig> usable = new ArrayList<>();
        for (HomeserverConfig homeserver : properties.getRouting().getHomeservers()) {
            IdentityServiceProperties.MasConfig mas = homeserver.getMas();
            if (!mas.getReadOnlyJdbcUrl().isBlank() && !mas.getUpstreamProviderId().isBlank()) {
                usable.add(homeserver);
            }
        }
        return usable;
    }

    @Override
    public List<MasLink> linksFor(String subject) {
        List<MasLink> links = new ArrayList<>();
        for (HomeserverConfig homeserver : usableHomeservers()) {
            String federationId = federationIds.of(homeserver);
            IdentityServiceProperties.MasConfig mas = homeserver.getMas();
            try (Connection connection = open(mas);
                    PreparedStatement statement = connection.prepareStatement(LINKS_QUERY)) {
                statement.setString(1, mas.getUpstreamProviderId());
                statement.setString(2, subject);
                try (ResultSet rows = statement.executeQuery()) {
                    while (rows.next()) {
                        links.add(new MasLink(federationId, rows.getString("subject"),
                                rows.getString("user_id"), rows.getString("username")));
                    }
                }
            } catch (SQLException | RuntimeException ex) {
                log.warn("Could not read MAS links on homeserver {}: {}", federationId, ex.getMessage());
            }
        }
        return links;
    }

    @Override
    public Map<String, String> localpartOnConflictByHomeserver() {
        Map<String, String> effective = new LinkedHashMap<>();
        for (HomeserverConfig homeserver : usableHomeservers()) {
            String federationId = federationIds.of(homeserver);
            IdentityServiceProperties.MasConfig mas = homeserver.getMas();
            try (Connection connection = open(mas);
                    PreparedStatement statement = connection.prepareStatement(CLAIMS_IMPORTS_QUERY)) {
                statement.setString(1, mas.getUpstreamProviderId());
                try (ResultSet rows = statement.executeQuery()) {
                    if (rows.next()) {
                        effective.put(federationId, onConflictOf(rows.getString("claims_imports")));
                    }
                }
            } catch (SQLException | RuntimeException ex) {
                log.warn("Could not read the localpart import policy on homeserver {}: {}", federationId,
                        ex.getMessage());
            }
        }
        return effective;
    }

    /**
     * The effective value, with the MAS default applied. {@code fail} is the default when the key is
     * absent, so reporting "absent" as "unset" would hide the difference that matters.
     */
    private String onConflictOf(String claimsImportsJson) {
        if (claimsImportsJson == null || claimsImportsJson.isBlank()) {
            return "fail";
        }
        try {
            JsonNode onConflict = objectMapper.readTree(claimsImportsJson).path("localpart").path("on_conflict");
            return onConflict.isMissingNode() || onConflict.isNull() ? "fail" : onConflict.asText("fail");
        } catch (RuntimeException | com.fasterxml.jackson.core.JsonProcessingException ex) {
            log.warn("A MAS claims_imports value did not parse");
            return "unknown";
        }
    }

    private Connection open(IdentityServiceProperties.MasConfig mas) throws SQLException {
        return connections.open(mas.getReadOnlyJdbcUrl(), mas.getReadOnlyUsername(), mas.getReadOnlyPassword());
    }
}
