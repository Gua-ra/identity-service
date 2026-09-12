// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

/**
 * One {@code upstream_oauth_links} row, as the shadow comparison needs it.
 *
 * <p>A link with a null MAS user id is an unfinished login, not evidence of placement, and readers drop
 * those before building this. The MAS column that holds a phone number is never selected and never
 * appears here.
 *
 * @param federationId the roster id of the homeserver whose MAS holds this link
 * @param subject      the link subject, which is the account's Matrix user id and stays so (ADM-008
 *                     decision 10 keeps {@code sub} and MAS link subjects unchanged)
 * @param masUserId    the MAS user the link is attached to
 * @param masUsername  that MAS user's username, or null when it could not be read
 */
public record MasLink(String federationId, String subject, String masUserId, String masUsername) {
}
