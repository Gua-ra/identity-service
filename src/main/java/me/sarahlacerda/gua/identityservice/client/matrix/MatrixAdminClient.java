package me.sarahlacerda.gua.identityservice.client.matrix;

import java.util.List;

import me.sarahlacerda.gua.identityservice.domain.MatrixLoginResponse;

public interface MatrixAdminClient {

    void upsertUser(String userId, String password, String phoneToLink, String displayName);

    List<String> getLinkedPhones(String userId);

    /**
     * Reverse lookup: resolves a phone number (E.164) to the Matrix user id it is
     * bound to on the homeserver, via the {@code msisdn} third-party identifier
     * binding ({@code GET /_synapse/admin/v1/threepid/msisdn/users/{address}}).
     * <p>
     * This binding is stored by the homeserver and is independent of the identity
     * directory's peppered phone digest, which makes it the authoritative fallback
     * for deciding whether a phone belongs to an existing account when the local
     * directory row is missing (e.g. a rotated/drifted directory pepper). Returns
     * empty when no account is bound to the number.
     */
    java.util.Optional<String> findUserIdByPhone(String phone);

    void linkPhone(String userId, String phone);

    void unlinkPhone(String userId, String phone);

    MatrixLoginResponse login(String userId, String password);

    boolean userExists(String userId);

    /**
     * Deactivates the Matrix user account on the homeserver. When {@code erase} is
     * true the
     * homeserver also wipes the user's profile and outbound encryption keys (GDPR
     * erase).
     */
    void deactivateUser(String userId, boolean erase);

    /**
     * Replaces the user's password on the homeserver via the admin API. Returns the
     * freshly
     * generated password so callers can hand it back to the client for a single
     * User-Interactive
     * Authentication challenge ({@code m.login.password}). Existing access tokens
     * are kept alive
     * ({@code logout_devices=false}) so the active session is not interrupted.
     */
    String rotatePassword(String userId);

    /**
     * Resolves a Matrix user access token to its owning user id by calling
     * {@code GET /_matrix/client/v3/account/whoami} with the supplied bearer token.
     * Returns empty if the token is invalid, expired or the homeserver rejects it.
     */
    java.util.Optional<String> whoami(String userAccessToken);

    /**
     * Sends a server notice ({@code POST /_synapse/admin/v1/send_server_notice}) to
     * the given user. The notice is delivered into the user's server-notices room and
     * syncs to every connected device, which makes it our channel for out-of-band
     * security alerts (e.g. a blocked change-number attempt).
     * <p>
     * Fail-safe: implementations must never throw out of this method. If the
     * homeserver has server notices disabled, returns a 4xx, or is unreachable, the
     * failure is logged at WARN and swallowed so the caller's flow is never broken.
     */
    void sendServerNotice(String userId, String message);
}
