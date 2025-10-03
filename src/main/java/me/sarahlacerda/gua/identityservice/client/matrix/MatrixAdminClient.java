package me.sarahlacerda.gua.identityservice.client.matrix;

import java.util.List;

import me.sarahlacerda.gua.identityservice.domain.MatrixLoginResponse;

public interface MatrixAdminClient {

    void upsertUser(String userId, String password, String phoneToLink, String displayName);

    List<String> getLinkedPhones(String userId);

    void linkPhone(String userId, String phone);

    void unlinkPhone(String userId, String phone);

    MatrixLoginResponse login(String userId, String password);
}
