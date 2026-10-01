package me.sarahlacerda.gua.identityservice.client.matrix;

import java.util.List;

import me.sarahlacerda.gua.identityservice.domain.MatrixLoginResponse;

public interface MatrixAdminClient {

    void upsertUser(String userId, String password, String phoneToLink, String displayName);

    List<String> getLinkedPhones(String userId);

    /** Looks up the homeserver's msisdn binding, which does not depend on the directory pepper. */
    java.util.Optional<String> findUserIdByPhone(String phone);

    void linkPhone(String userId, String phone);

    void unlinkPhone(String userId, String phone);

    MatrixLoginResponse login(String userId, String password);

    boolean userExists(String userId);

    void deactivateUser(String userId, boolean erase);

    /** Existing access tokens stay valid (logout_devices=false). */
    String rotatePassword(String userId);

    java.util.Optional<String> whoami(String userAccessToken);
}
