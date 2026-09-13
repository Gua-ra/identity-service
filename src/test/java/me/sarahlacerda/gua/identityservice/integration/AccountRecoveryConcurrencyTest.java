package me.sarahlacerda.gua.identityservice.integration;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import me.sarahlacerda.gua.identityservice.domain.IdentityUser;
import me.sarahlacerda.gua.identityservice.exception.AccountRecoveryNotReadyException;
import me.sarahlacerda.gua.identityservice.repository.IdentityUserRepository;
import me.sarahlacerda.gua.identityservice.service.security.AccountRecoveryService;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;

/**
 * The recovery writers against real row locks. Cancel and complete race for the same ready
 * episode, and a finished sign-in races a completion; whichever order the database picks, the
 * account ends in one consistent state: never both cancelled and completed, and a recovered PIN
 * hash is never written back over.
 *
 * <p>
 * Needs Docker for Postgres and Redis, and is skipped where Docker is not available.
 */
@SpringBootTest
@Testcontainers(disabledWithoutDocker = true)
class AccountRecoveryConcurrencyTest {

    private static final String OLD_PIN = "482913";
    private static final String NEW_PIN = "739164";
    private static final int ROUNDS = 10;

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
            .withDatabaseName("identity")
            .withUsername("identity")
            .withPassword("identity");

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379).toString());

        registry.add("identity.matrix.admin-api-base-url", () -> "http://localhost:1");
        registry.add("identity.matrix.client-api-base-url", () -> "http://localhost:1");
        registry.add("identity.matrix.homeserver-domain", () -> "example.com");
        registry.add("identity.matrix.admin-access-token", () -> "test-admin-token");
        registry.add("identity.directory.pepper", () -> "test-pepper");
        registry.add("identity.sms.twilio.enabled", () -> "false");
        registry.add("identity.rate-limits.enabled", () -> "false");
        registry.add("oidc.issuer", () -> "http://localhost");
    }

    @Autowired
    AccountRecoveryService accountRecoveryService;

    @Autowired
    UserSecurityService userSecurityService;

    @Autowired
    IdentityUserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    /** A PIN account whose recovery was requested long enough ago to be ready now. */
    private String accountWithAReadyRecovery() {
        String userId = "@" + UUID.randomUUID() + ":example.com";
        userSecurityService.setInitialPin(userId, OLD_PIN);
        IdentityUser user = userRepository.findByUserId(userId).orElseThrow();
        Instant now = Instant.now();
        user.setLastLoginAt(now.minus(Duration.ofDays(30)));
        user.setPinResetRequestedAt(now.minus(Duration.ofDays(8)));
        userRepository.saveAndFlush(user);
        return userId;
    }

    private static <T> List<Future<T>> race(List<Callable<T>> tasks) throws InterruptedException {
        ExecutorService executor = Executors.newFixedThreadPool(tasks.size());
        CountDownLatch start = new CountDownLatch(1);
        List<Future<T>> futures = new ArrayList<>();
        for (Callable<T> task : tasks) {
            futures.add(executor.submit(() -> {
                start.await();
                return task.call();
            }));
        }
        start.countDown();
        executor.shutdown();
        assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
        return futures;
    }

    @Test
    void cancelAndCompleteNeverBothWin() throws Exception {
        for (int round = 0; round < ROUNDS; round++) {
            String userId = accountWithAReadyRecovery();

            List<Future<Object>> outcomes = race(List.<Callable<Object>>of(
                    () -> accountRecoveryService.cancel(userId, "198.51.100.4"),
                    () -> {
                        try {
                            return accountRecoveryService.complete(userId, NEW_PIN);
                        } catch (AccountRecoveryNotReadyException refused) {
                            return refused;
                        }
                    }));

            boolean cancelled = (Boolean) outcomes.get(0).get();
            boolean completed = outcomes.get(1).get() instanceof Integer;
            IdentityUser after = userRepository.findByUserId(userId).orElseThrow();

            assertThat(cancelled ^ completed).as("round %d: exactly one of cancel and complete wins", round).isTrue();
            assertThat(after.getPinResetRequestedAt()).isNull();
            if (completed) {
                assertThat(passwordEncoder.matches(NEW_PIN, after.getPinHash())).isTrue();
            } else {
                assertThat(passwordEncoder.matches(OLD_PIN, after.getPinHash())).isTrue();
                assertThat(after.getLastLoginAt()).isAfter(Instant.now().minus(Duration.ofMinutes(1)));
            }
        }
    }

    @Test
    void aSignInRacingACompletionNeverWritesTheOldPinHashBack() throws Exception {
        for (int round = 0; round < ROUNDS; round++) {
            String userId = accountWithAReadyRecovery();

            List<Future<Object>> outcomes = race(List.<Callable<Object>>of(
                    () -> {
                        userSecurityService.recordSuccessfulLogin(userId);
                        return Boolean.TRUE;
                    },
                    () -> {
                        try {
                            return accountRecoveryService.complete(userId, NEW_PIN);
                        } catch (AccountRecoveryNotReadyException refused) {
                            return refused;
                        }
                    }));

            outcomes.get(0).get();
            boolean completed = outcomes.get(1).get() instanceof Integer;
            IdentityUser after = userRepository.findByUserId(userId).orElseThrow();

            // The sign-in may end the episode first, in which case the completion is refused; if the
            // completion commits first, the sign-in must not put the old PIN hash back.
            assertThat(after.getPinResetRequestedAt()).isNull();
            assertThat(passwordEncoder.matches(completed ? NEW_PIN : OLD_PIN, after.getPinHash()))
                    .as("round %d, completed=%s", round, completed)
                    .isTrue();
        }
    }
}
