package me.sarahlacerda.gua.identityservice.integration;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import me.sarahlacerda.gua.identityservice.domain.IdentityUser;
import me.sarahlacerda.gua.identityservice.exception.InvalidPinException;
import me.sarahlacerda.gua.identityservice.exception.PinLockedException;
import me.sarahlacerda.gua.identityservice.repository.IdentityUserRepository;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@SpringBootTest
@Testcontainers
class PinAttemptsConcurrencyTest {

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
        registry.add("identity.matrix.user-localpart-prefix", () -> "gua");
        registry.add("identity.directory.pepper", () -> "test-pepper");
        registry.add("identity.sms.twilio.enabled", () -> "false");
        registry.add("identity.rate-limits.enabled", () -> "false");
        registry.add("oidc.issuer", () -> "http://localhost");
    }

    @Autowired
    UserSecurityService userSecurityService;

    @Autowired
    IdentityUserRepository userRepository;

    @Test
    void concurrentWrongPinAttemptsAreSerializedAndLockoutKicksIn() throws Exception {
        String userId = "@" + UUID.randomUUID() + ":example.com";
        userSecurityService.setInitialPin(userId, "284917");

        int threads = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger invalid = new AtomicInteger();
        AtomicInteger locked = new AtomicInteger();
        AtomicInteger other = new AtomicInteger();
        List<Throwable> unexpected = new ArrayList<>();

        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                try {
                    start.await();
                    userSecurityService.validatePinOrThrow(userId, "000000");
                } catch (InvalidPinException e) {
                    invalid.incrementAndGet();
                } catch (PinLockedException e) {
                    locked.incrementAndGet();
                } catch (Throwable t) {
                    other.incrementAndGet();
                    synchronized (unexpected) {
                        unexpected.add(t);
                    }
                } finally {
                    done.countDown();
                }
            });
        }

        start.countDown();
        assertThat(done.await(15, TimeUnit.SECONDS)).isTrue();
        executor.shutdown();

        assertThat(unexpected).as("no unexpected exceptions").isEmpty();
        assertThat(invalid.get() + locked.get()).isEqualTo(threads);
        // With maxPinAttempts=5, first 5 wrong attempts increment failure_count then
        // trip lock on the 5th.
        // Subsequent attempts must observe the locked state.
        assertThat(invalid.get()).isGreaterThanOrEqualTo(5);
        assertThat(locked.get()).as("subsequent attempts after lockout must be rejected with PinLockedException")
                .isGreaterThanOrEqualTo(1);

        IdentityUser after = userRepository.findByUserId(userId).orElseThrow();
        assertThat(after.getPinLockedUntil())
                .as("user must be locked after concurrent wrong PIN attempts")
                .isNotNull()
                .isAfter(Instant.now());
    }
}
