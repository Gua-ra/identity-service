package me.sarahlacerda.gua.identityservice.service.routing;

import me.sarahlacerda.gua.identityservice.domain.Homeserver;

/**
 * Picks the homeserver a new Gua account is created on. The choice is recorded in this service's
 * directory so returning users resolve to the same place.
 *
 * <p>Placement is decided once, at account creation. Moving an existing account between homeservers
 * is not supported: Matrix has no native migration that preserves identity and key continuity.
 */
public interface HomeserverRouter {

    /**
     * Selects the homeserver for a new account.
     *
     * @param context optional placement hints (phone, region)
     * @return the chosen, enabled homeserver
     * @throws IllegalStateException if no homeserver is eligible
     */
    Homeserver selectForNewAccount(AccountPlacementContext context);
}
