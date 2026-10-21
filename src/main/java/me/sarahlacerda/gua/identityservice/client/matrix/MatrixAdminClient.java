package me.sarahlacerda.gua.identityservice.client.matrix;

import java.util.List;

import me.sarahlacerda.gua.identityservice.domain.MatrixLoginResponse;

public interface MatrixAdminClient {

    void upsertUser(String userId, String password, String phoneToLink, String displayName);

    List<String> getLinkedPhones(String userId);

    /**
     * Reverse lookup: resolves an E.164 phone number to the Matrix user id it is bound to through the
     * {@code msisdn} third-party identifier
     * ({@code GET /_synapse/admin/v1/threepid/msisdn/users/{address}}). The homeserver stores this
     * binding independently of the directory's peppered digest, so it is the fallback when the local
     * directory row is missing. Returns empty when no account is bound to the number.
     */
    java.util.Optional<String> findUserIdByPhone(String phone);

    void linkPhone(String userId, String phone);

    void unlinkPhone(String userId, String phone);

    MatrixLoginResponse login(String userId, String password);

    boolean userExists(String userId);

    /**
     * Deactivates the Matrix account on the homeserver. When {@code erase} is true the homeserver also
     * wipes the user's profile and outbound encryption keys (GDPR erase).
     */
    void deactivateUser(String userId, boolean erase);

    /**
     * Replaces the user's password through the admin API and returns the freshly generated one, so the
     * caller can hand it to the client for a single User-Interactive Authentication challenge
     * ({@code m.login.password}). Existing access tokens stay valid ({@code logout_devices=false}).
     */
    String rotatePassword(String userId);

    /**
     * Resolves a Matrix user access token to its owning user id by calling
     * {@code GET /_matrix/client/v3/account/whoami} with the supplied bearer token.
     * Returns empty if the token is invalid, expired or the homeserver rejects it.
     */
    java.util.Optional<String> whoami(String userAccessToken);
}
