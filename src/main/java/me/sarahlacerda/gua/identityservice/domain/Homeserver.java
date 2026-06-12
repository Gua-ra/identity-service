package me.sarahlacerda.gua.identityservice.domain;

/**
 * A homeserver that the Gua federation can place accounts on. The identity
 * service is the routing authority: it decides which homeserver a new account
 * lives on and records that decision in the directory so returning users (and
 * username/phone lookups) resolve to the right place.
 *
 * <p>This is a Gua-controlled-federation concept (à la Tchap): every homeserver
 * here is operated by Gua (or a consortium that delegates allocation to this
 * service). It is NOT the open Matrix federation.
 *
 * @param id              stable identifier used in the directory (never the domain, so a
 *                        homeserver can be re-addressed without rewriting rows)
 * @param domain          the Matrix server name (the {@code :server} part of an MXID)
 * @param adminApiBaseUrl base URL of this homeserver's Synapse admin API
 * @param clientApiBaseUrl base URL handed back to clients for this homeserver
 * @param adminAccessToken admin token used to provision on this homeserver
 * @param region          optional placement hint (e.g. "br", "eu")
 * @param weight          relative weight for load-based placement (higher = more)
 * @param enabled         whether new accounts may be placed here
 */
public record Homeserver(
        String id,
        String domain,
        String adminApiBaseUrl,
        String clientApiBaseUrl,
        String adminAccessToken,
        String region,
        int weight,
        boolean enabled) {

    public Homeserver {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("homeserver id must not be blank");
        }
        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException("homeserver domain must not be blank");
        }
    }

    /** Builds the full MXID for a localpart hosted on this homeserver. */
    public String userId(String localpart) {
        return "@" + localpart + ":" + domain;
    }
}
