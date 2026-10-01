// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.security;

import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesis;
import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesisCodec;
import me.sarahlacerda.gua.identityservice.config.LoginFlowProperties;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.domain.PasskeyCredential;
import me.sarahlacerda.gua.identityservice.exception.LoginFlowException;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;
import me.sarahlacerda.gua.identityservice.repository.PasskeyCredentialRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

@DataJpaTest(properties = {
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.sql.init.mode=never",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect"
})
@Import(PasskeyLastFactorRaceTest.Beans.class)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class PasskeyLastFactorRaceTest {

    private static final String USER = "@sarah:gua.global";

    @Autowired
    private PasskeyService service;

    @Autowired
    private PasskeyCredentialRepository repository;

    @Autowired
    private AccountGenesisRepository genesisRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    private final ExecutorService requests = Executors.newFixedThreadPool(2);

    @AfterEach
    void clear() {
        requests.shutdownNow();
        repository.deleteAll();
        genesisRepository.deleteAll();
    }

    @Test
    void twoRemovalsAtOnceCannotLeaveAnAccountWithNoFactor() throws Exception {
        BootstrapGenesis genesis = BootstrapGenesisCodec.mint();
        String principal = genesis.accountId().value();
        genesisRepository.saveAndFlush(AccountGenesisRecord.attachedBootstrap(principal, USER,
                (short) genesis.version(), (short) genesis.suite(),
                Base64.getUrlEncoder().withoutPadding().encodeToString(genesis.canonicalBytes()), Instant.now()));
        repository.saveAndFlush(credential(principal, "cred-one"));
        repository.saveAndFlush(credential(principal, "cred-two"));

        CountDownLatch firstHasRemoved = new CountDownLatch(1);
        CountDownLatch firstMayCommit = new CountDownLatch(1);
        Future<Boolean> first = requests.submit(() -> new TransactionTemplate(transactionManager).execute(status -> {
            boolean removed = service.removeCredential(USER, "cred-one", false);
            firstHasRemoved.countDown();
            await(firstMayCommit);
            return removed;
        }));
        assertThat(firstHasRemoved.await(5, TimeUnit.SECONDS)).isTrue();

        Future<Boolean> second = requests.submit(() -> service.removeCredential(USER, "cred-two", false));
        try {
            second.get(500, TimeUnit.MILLISECONDS);
        } catch (TimeoutException | ExecutionException stillWaitingOrAlreadyRefused) {
        }
        firstMayCommit.countDown();

        assertThat(first.get(5, TimeUnit.SECONDS)).isTrue();
        assertThatThrownBy(() -> second.get(5, TimeUnit.SECONDS))
                .hasCauseInstanceOf(LoginFlowException.class);
        assertThat(repository.findByAccountPrincipal(principal))
                .extracting(PasskeyCredential::getCredentialId)
                .containsExactly("cred-two");
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    private static PasskeyCredential credential(String principal, String credentialId) {
        return PasskeyCredential.builder()
                .accountPrincipal(principal)
                .userId(USER)
                .userHandle("handle")
                .credentialId(credentialId)
                .publicKeyCose("cose")
                .signatureCount(0)
                .backupEligible(false)
                .backupState(false)
                .build();
    }

    @TestConfiguration
    static class Beans {

        @Bean
        PasskeyService passkeyService(PasskeyCredentialRepository repository,
                AccountGenesisRepository genesisRepository) {
            return new PasskeyService(repository, new PasskeyPrincipals(genesisRepository),
                    new LoginFlowProperties(), mock(StringRedisTemplate.class), new ObjectMapper());
        }
    }
}
