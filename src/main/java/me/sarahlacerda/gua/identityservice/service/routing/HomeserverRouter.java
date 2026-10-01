package me.sarahlacerda.gua.identityservice.service.routing;

import me.sarahlacerda.gua.identityservice.domain.Homeserver;

/** Placement is decided once, at account creation. Moving an account between homeservers is not supported. */
public interface HomeserverRouter {

    Homeserver selectForNewAccount(AccountPlacementContext context);
}
