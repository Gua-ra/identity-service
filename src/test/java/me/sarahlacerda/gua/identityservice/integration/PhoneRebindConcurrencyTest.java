package me.sarahlacerda.gua.identityservice.integration;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import me.sarahlacerda.gua.identityservice.domain.DirectoryEntry;
import me.sarahlacerda.gua.identityservice.repository.DirectoryEntryRepository;
import me.sarahlacerda.gua.identityservice.service.DirectoryService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@SpringBootTest
@Testcontainers
class PhoneRebindConcurrencyTest {

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
    DirectoryService directoryService;

    @Autowired
    DirectoryEntryRepository directoryRepository;

    @Test
    void concurrentBindOfSamePhoneToDifferentUsersResultsInExactlyOneWinner() throws Exception {
        String digest = UUID.randomUUID().toString().replace("-", "");
        String userA = "@" + UUID.randomUUID() + ":example.com";
        String userB = "@" + UUID.randomUUID() + ":example.com";

        int threads = 2;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger ok = new AtomicInteger();
        AtomicInteger conflicts = new AtomicInteger();
        List<Throwable> unexpected = new ArrayList<>();

        Runnable bindA = () -> {
            try {
                start.await();
                directoryService.upsertByDigest(digest, userA, "Alice");
                ok.incrementAndGet();
            } catch (DataIntegrityViolationException e) {
                conflicts.incrementAndGet();
            } catch (Throwable t) {
                synchronized (unexpected) { unexpected.add(t); }
            } finally {
                done.countDown();
            }
        };

        Runnable bindB = () -> {
            try {
                start.await();
                directoryService.upsertByDigest(digest, userB, "Bob");
                ok.incrementAndGet();
            } catch (DataIntegrityViolationException e) {
                conflicts.incrementAndGet();
            } catch (Throwable t) {
                synchronized (unexpected) { unexpected.add(t); }
            } finally {
                done.countDown();
            }
        };

        executor.submit(bindA);
        executor.submit(bindB);
        start.countDown();
        assertThat(done.await(15, TimeUnit.SECONDS)).isTrue();
        executor.shutdown();

        assertThat(unexpected).isEmpty();
        // Both may succeed under last-write-wins (since upsert re-fetches),
        // OR one may throw DataIntegrityViolation under contention.
        // What MUST hold: there is exactly ONE row for this digest, owned by either A or B.
        List<DirectoryEntry> all = directoryRepository.findByPhoneDigestIn(List.of(digest));
        assertThat(all).hasSize(1);
        assertThat(all.get(0).getUserId()).isIn(userA, userB);
        // And at least one operation either succeeded or was rejected — i.e. all 2 threads were observed.
        assertThat(ok.get() + conflicts.get()).isEqualTo(threads);
    }
}
