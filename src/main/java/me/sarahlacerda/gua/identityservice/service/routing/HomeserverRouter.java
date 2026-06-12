package me.sarahlacerda.gua.identityservice.service.routing;

import me.sarahlacerda.gua.identityservice.domain.Homeserver;

/**
 * Decides which homeserver a brand-new Gua account should be created on.
 *
 * <p>This is the routing layer: the UI treats {@code @id:server} as an
 * implementation detail, and this component owns the rule that maps a new
 * identity to a concrete homeserver. The chosen homeserver is then recorded in
 * the directory so the account's location is authoritative and stable.
 *
 * <p>Placement is decided once, at account creation. Relocating an existing
 * account between homeservers is NOT supported by stock Matrix (immutable MXIDs)
 * and is intentionally out of scope here.
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
