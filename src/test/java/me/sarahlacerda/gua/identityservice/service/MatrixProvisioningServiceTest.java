package me.sarahlacerda.gua.identityservice.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.domain.MatrixLoginResponse;
import me.sarahlacerda.gua.identityservice.domain.MatrixSession;
import me.sarahlacerda.gua.identityservice.client.matrix.MatrixAdminClient;

class MatrixProvisioningServiceTest {

    private IdentityServiceProperties properties;
    private MatrixAdminClient matrixAdminClient;
    private MatrixProvisioningService service;

    @BeforeEach
    void setUp() {
        properties = new IdentityServiceProperties();
        matrixAdminClient = Mockito.mock(MatrixAdminClient.class);
        service = new MatrixProvisioningService(properties, matrixAdminClient);
    }

    @Test
    void ensureSessionForUserCreatesAndLogsIn() {
        when(matrixAdminClient.login(eq("@user:domain"), any()))
            .thenReturn(new MatrixLoginResponse("token", "@user:domain", "device"));

        MatrixSession session = service.ensureSessionForUser("@user:domain", "+12025550123", "User", true);

        ArgumentCaptor<String> passwordCaptor = ArgumentCaptor.forClass(String.class);
        verify(matrixAdminClient).upsertUser(eq("@user:domain"), passwordCaptor.capture(), eq("+12025550123"), eq("User"));
        verify(matrixAdminClient).login("@user:domain", passwordCaptor.getValue());

        assertThat(session.accessToken()).isEqualTo("token");
        assertThat(session.userId()).isEqualTo("@user:domain");
        assertThat(session.deviceId()).isEqualTo("device");
    }

    @Test
    void ensureExclusivePhoneBindingLinksAndUnlinks() {
        when(matrixAdminClient.getLinkedPhones("@user:domain")).thenReturn(List.of("+19999999999", "+18888888888"));

        service.ensureExclusivePhoneBinding("@user:domain", "+17777777777");

        verify(matrixAdminClient).linkPhone("@user:domain", "+17777777777");
        verify(matrixAdminClient, times(1)).unlinkPhone("@user:domain", "+19999999999");
        verify(matrixAdminClient, times(1)).unlinkPhone("@user:domain", "+18888888888");
    }

    @Test
    void ensureExclusivePhoneBindingSkipsLinkWhenAlreadyPresent() {
        when(matrixAdminClient.getLinkedPhones("@user:domain")).thenReturn(List.of("+17777777777", "+18888888888"));

        service.ensureExclusivePhoneBinding("@user:domain", "+17777777777");

        verify(matrixAdminClient, never()).linkPhone("@user:domain", "+17777777777");
        verify(matrixAdminClient).unlinkPhone("@user:domain", "+18888888888");
    }

    @Test
    void generateOpaqueUserIdBuildsOpaqueLocalPart() {
        String userId = service.generateOpaqueUserId();

        assertThat(userId).startsWith("@" + properties.getMatrix().getUserLocalpartPrefix())
            .endsWith(":" + properties.getMatrix().getHomeserverDomain());
        assertThat(userId.length()).isGreaterThan(10); // ensures randomness applied
    }

    @Test
    void generateOpaqueUserIdFallsBackWhenPrefixLooksLikeDomain() {
        properties.getMatrix().setUserLocalpartPrefix("dev.example.com");

        String userId = service.generateOpaqueUserId();

        assertThat(userId).startsWith("@u").endsWith(":" + properties.getMatrix().getHomeserverDomain());
    }
}
