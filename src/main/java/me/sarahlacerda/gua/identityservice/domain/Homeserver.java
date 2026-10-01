package me.sarahlacerda.gua.identityservice.domain;

/** The id is stable and is never the domain, so a homeserver can be re-addressed without rewriting rows. */
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
