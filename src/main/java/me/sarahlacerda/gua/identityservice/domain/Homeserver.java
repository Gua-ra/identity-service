package me.sarahlacerda.gua.identityservice.domain;

/**
 * A homeserver this deployment can create accounts on. The service picks one for a new account from
 * its configured registry and records the choice in its directory, so returning users resolve to
 * the same place. This is a closed federation: the homeservers listed are the ones Gua operates.
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

    public String userId(String localpart) {
        return "@" + localpart + ":" + domain;
    }
}
