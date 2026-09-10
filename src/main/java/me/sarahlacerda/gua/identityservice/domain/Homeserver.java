package me.sarahlacerda.gua.identityservice.domain;

/**
 * A homeserver that this deployment can create accounts on.
 *
 * <p>Current implementation: this service picks a homeserver for a new account
 * from its configured registry and records that choice in its own directory, so
 * returning users (and username/phone lookups) resolve to the same place. That is
 * a local, per-deployment choice, not the federation placement model. Under
 * <a href="https://github.com/Gua-ra/gua-resolver/blob/main/docs/decisions/ADM-001-identifier-binding-placement-trust.md">ADM-001</a> (L2, L6) placement is coordinated by the federation
 * and verifiable against signed policy and roster state; allocation is not
 * delegated to this service.
 *
 * <p>This is a closed-federation concept (à la Tchap): the homeservers listed
 * here are the ones Gua operates. It is NOT the open Matrix federation.
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
