package me.sarahlacerda.gua.identityservice.service.routing;

import me.sarahlacerda.gua.identityservice.domain.Homeserver;

/**
 * Picks the homeserver a brand-new Gua account is created on, in the current
 * implementation.
 *
 * <p>The UI treats {@code @id:server} as an implementation detail, and this
 * component holds the local rule that maps a new identity to a concrete
 * homeserver. The choice is recorded in this service's directory so returning
 * users resolve to the same place. It is a per-deployment decision that nothing
 * outside this service can re-derive; it is not the federation placement
 * transaction of <a href="https://github.com/Gua-ra/gua-resolver/blob/main/docs/decisions/ADM-001-identifier-binding-placement-trust.md">ADM-001</a> L6.
 *
 * <p>Placement is decided once, at account creation. Moving an existing account
 * between homeservers is not supported here: Matrix has no native migration that
 * preserves identity and key continuity (ADM-001 L9), and migration of existing
 * placements is tracked as ADM-001 S6.
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
