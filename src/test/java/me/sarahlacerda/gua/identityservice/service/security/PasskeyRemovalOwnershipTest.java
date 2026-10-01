// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.security;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpStatus;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.domain.PasskeyCredential;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.repository.PasskeyCredentialRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasskeyRemovalOwnershipTest {

    private static final AccountId ACCOUNT = account("removal-owner");
    private static final AccountId OTHER_ACCOUNT = account("removal-other");

    private static final String OLD_MXID = "@alice:one.example";
    private static final String NEW_MXID = "@alice:two.example";
    private static final String CREDENTIAL_ID = "Y3JlZC0x";

    @Mock
    private PasskeyCredentialRepository repository;
    @Mock
    private PasskeyPrincipals principals;
    @Mock
    private StringRedisTemplate redisTemplate;

    @Test
    void aCredentialIsRemovedAfterTheMatrixIdentityChanged() {
        PasskeyCredential credential = credential(ACCOUNT, OLD_MXID);
        givenThePrincipalOf(NEW_MXID, ACCOUNT);
        when(repository.findByCredentialId(CREDENTIAL_ID)).thenReturn(Optional.of(credential));

        assertThat(service().removeCredential(NEW_MXID, CREDENTIAL_ID, true)).isTrue();

        verify(repository).delete(credential);
        verify(repository, never()).findByUserId(anyString());
    }

    @Test
    void aCredentialOfAnotherPrincipalIsNotRemovedEvenWhenItsRowNamesTheCallersMatrixId() {
        givenThePrincipalOf(NEW_MXID, ACCOUNT);
        when(repository.findByCredentialId(CREDENTIAL_ID))
                .thenReturn(Optional.of(credential(OTHER_ACCOUNT, NEW_MXID)));

        assertThat(service().removeCredential(NEW_MXID, CREDENTIAL_ID, true)).isFalse();

        verify(repository, never()).delete(any());
    }

    @Test
    void anAccountWithNoPrincipalRemovesNothingAndIsNotLookedUpByMatrixId() {
        when(principals.forUserId(NEW_MXID)).thenReturn(Optional.empty());

        assertThat(service().removeCredential(NEW_MXID, CREDENTIAL_ID, true)).isFalse();

        verify(repository, never()).delete(any());
        verify(repository, never()).findByUserId(anyString());
        verify(repository, never()).findByCredentialId(anyString());
    }

    @Test
    void theLastFactorIsCountedByPrincipal() {
        PasskeyCredential credential = credential(ACCOUNT, OLD_MXID);
        givenThePrincipalOf(NEW_MXID, ACCOUNT);
        when(repository.findByCredentialId(CREDENTIAL_ID)).thenReturn(Optional.of(credential));
        when(repository.findByAccountPrincipalForUpdate(ACCOUNT.value())).thenReturn(List.of(credential));

        assertThatThrownBy(() -> service().removeCredential(NEW_MXID, CREDENTIAL_ID, false))
                .isInstanceOf(LoginFlowException.class)
                .satisfies(ex -> {
                    LoginFlowException flow = (LoginFlowException) ex;
                    assertThat(flow.getCode()).isEqualTo("factor_required");
                    assertThat(flow.getStatus()).isEqualTo(HttpStatus.CONFLICT);
                });

        verify(repository, never()).delete(any());
        verify(repository, never()).findByUserId(anyString());
    }

    @Test
    void oneOfSeveralCredentialsIsRemovedWithoutAnotherFactor() {
        PasskeyCredential credential = credential(ACCOUNT, OLD_MXID);
        givenThePrincipalOf(NEW_MXID, ACCOUNT);
        when(repository.findByCredentialId(CREDENTIAL_ID)).thenReturn(Optional.of(credential));
        when(repository.findByAccountPrincipalForUpdate(ACCOUNT.value()))
                .thenReturn(List.of(credential, credential(ACCOUNT, OLD_MXID)));

        assertThat(service().removeCredential(NEW_MXID, CREDENTIAL_ID, false)).isTrue();

        verify(repository).delete(credential);
    }

    private PasskeyService service() {
        return new PasskeyService(repository, principals, new LoginFlowProperties(), redisTemplate,
                new ObjectMapper());
    }

    private void givenThePrincipalOf(String userId, AccountId account) {
        when(principals.forUserId(userId))
                .thenReturn(Optional.of(new PasskeyPrincipals.Principal(account.value(), account.rawBytes())));
    }

    private static PasskeyCredential credential(AccountId owner, String rowUserId) {
        return PasskeyCredential.builder()
                .accountPrincipal(owner.value())
                .userId(rowUserId)
                .userHandle(new com.yubico.webauthn.data.ByteArray(owner.rawBytes()).getBase64Url())
                .credentialId(CREDENTIAL_ID)
                .publicKeyCose("cose")
                .signatureCount(0)
                .build();
    }

    private static AccountId account(String seed) {
        return AccountId.derive(AccountId.CLASS_BOOTSTRAP, seed.getBytes(StandardCharsets.UTF_8));
    }
}
