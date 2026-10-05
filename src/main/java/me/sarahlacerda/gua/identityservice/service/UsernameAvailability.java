package me.sarahlacerda.gua.identityservice.service;

import java.util.LinkedHashSet;
import java.util.Set;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Component;

import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;
import me.sarahlacerda.gua.identityservice.domain.Homeserver;
import me.sarahlacerda.gua.identityservice.service.account.AccountGenesisService;
import me.sarahlacerda.gua.identityservice.service.routing.HomeserverRegistry;

/**
 * The one answer to "can a new account take this username", shared by {@code /login/profile},
 * {@code /signup/check-username} and {@code /signup/complete}.
 *
 * <p>A username is taken when this directory holds it, when a deleted account held it on any configured
 * homeserver, or when the homeserver the new account would live on already has the user. The deleted
 * account check is what keeps a name from passing to a stranger: the directory row is gone after a
 * deletion and the homeserver check answers "free" whenever its admin API cannot be reached.
 */
@Component
@RequiredArgsConstructor
public class UsernameAvailability {

    private final DirectoryService directoryService;
    private final AccountGenesisService accountGenesisService;
    private final HomeserverRegistry homeserverRegistry;
    private final MatrixAdminClient matrixAdminClient;

    /**
     * @param localpart a username already normalized by {@link UsernamePolicy}
     * @param userId    the Matrix user id the new account would have
     */
    public boolean isTaken(String localpart, String userId) {
        if (directoryService.isUsernameTaken(localpart)) {
            return true;
        }
        Set<String> candidates = new LinkedHashSet<>();
        candidates.add(userId);
        for (Homeserver homeserver : homeserverRegistry.all()) {
            candidates.add(homeserver.userId(localpart));
        }
        if (accountGenesisService.isAnyDeleted(candidates)) {
            return true;
        }
        return matrixAdminClient.userExists(userId);
    }
}
