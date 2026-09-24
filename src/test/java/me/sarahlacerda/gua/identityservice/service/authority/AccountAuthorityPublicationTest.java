// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityHeadRecord;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityHeadRecordCodec;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityProofs;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecord;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecordType;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityRecords;
import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesis;
import me.sarahlacerda.gua.identityservice.account.genesis.BootstrapGenesisCodec;
import me.sarahlacerda.gua.identityservice.account.genesis.Ed25519Keys;
import me.sarahlacerda.gua.identityservice.account.genesis.TestEd25519;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;
import me.sarahlacerda.gua.identityservice.domain.AccountGenesisRecord;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChainHead;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChainRecord;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChallenge.Purpose;
import me.sarahlacerda.gua.identityservice.domain.AuthorityHeadPublication;
import me.sarahlacerda.gua.identityservice.repository.AccountGenesisRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChainHeadRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChainRecordRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityChallengeRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceCandidateRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityDeviceRepository;
import me.sarahlacerda.gua.identityservice.repository.AuthorityHeadPublicationRepository;
import me.sarahlacerda.gua.identityservice.service.security.AuthFactor;
import me.sarahlacerda.gua.identityservice.service.security.UserSecurityService;
import me.sarahlacerda.gua.identityservice.service.security.audit.LoggingSecurityAuditLogger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The publication path, walked through real transitions against a real engine and a real resolver socket
 * (ADM-009 decision 12).
 *
 * <p>Four claims, and none of them can be shown with a mock. That a head reaches the log <em>on the
 * transitions that move it</em> and not before, which is a statement about when the window closes; that a
 * record inside its window never reaches it, which is a statement about what the head row means while a slot
 * is reserved; that a republish is byte-identical, which is a statement about what crosses the socket; and
 * that with the flag off nothing crosses it at all.
 *
 * <p>Not transactional, unlike the sibling transition test. The delivery is registered to run after the
 * transition commits, so a test whose transaction is rolled back would show no delivery at all and prove
 * the opposite of what it set out to. Each service call therefore runs and commits its own transaction, and
 * every assertion re-reads its rows.
 */
@DataJpaTest(properties = {
        "spring.flyway.enabled=false",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "spring.sql.init.mode=never",
        "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect"
})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
// The container's own proxy, because the acknowledgement is written in a REQUIRES_NEW transaction from inside
// the completing one's synchronization, and that is the whole reason it reaches the row at all.
@Import(AuthorityHeadPublications.class)
class AccountAuthorityPublicationTest {

    private static final String USER = "@sarah:gua.global";
    private static final String SESSION = "a".repeat(64);
    private static final String NATIVE_CLIENT = "gua-ios";
    private static final String FEDERATION_ID = "hs-alpha";
    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    private AccountGenesisRepository genesisRepository;

    @Autowired
    private AuthorityChainHeadRepository headRepository;

    @Autowired
    private AuthorityChainRecordRepository recordRepository;

    @Autowired
    private AuthorityDeviceRepository deviceRepository;

    @Autowired
    private AuthorityChallengeRepository challengeRepository;

    @Autowired
    private AuthorityDeviceCandidateRepository candidateRepository;

    @Autowired
    private AuthorityHeadPublicationRepository publicationRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private AuthorityHeadPublications publications;

    private final TestEd25519.Pair firstDevice = TestEd25519.generate();
    private final TestEd25519.Pair secondDevice = TestEd25519.generate();
    private final TestEd25519.Pair recoveryKey = TestEd25519.generate();
    private final TestEd25519.Pair membershipKey = TestEd25519.generate();

    private MockWebServer resolver;
    private IdentityServiceProperties properties;
    private AuthorityChallengeService challenges;
    private AccountAuthorityService service;
    private MutableClock clock;
    private TransactionTemplate transactions;
    private byte[] reference;

    @BeforeEach
    void setUp() throws IOException {
        resolver = new MockWebServer();
        resolver.start();
        transactions = new TransactionTemplate(transactionManager);
        clock = new MutableClock(Instant.parse("2026-09-24T12:00:00Z"));
        properties = new IdentityServiceProperties();
        properties.getAuthority().setEnabled(true);
        properties.getAuthority().setProductionAdoption(true);
        properties.getAuthority().getNativeClientIds().add(NATIVE_CLIENT);
        HomeserverConfig homeserver = new HomeserverConfig();
        homeserver.setId("primary");
        homeserver.setDomain("example.test");
        homeserver.setAdminApiBaseUrl("http://admin.invalid");
        homeserver.setClientApiBaseUrl("http://client.invalid");
        homeserver.setAdminAccessToken("not-a-real-token");
        homeserver.setFederationId(FEDERATION_ID);
        homeserver.setPlacementSigningPrivateKey(
                Base64.getEncoder().encodeToString(membershipKey.privateKey().getEncoded()));
        properties.getRouting().getHomeservers().add(homeserver);
        properties.getAuthority().getPublication().setHomeserverId(FEDERATION_ID);
        properties.getAuthority().getPublication()
                .setResolverBaseUrl(resolver.url("/").toString().replaceAll("/$", ""));

        rebuildService();

        BootstrapGenesis genesis = BootstrapGenesisCodec.mint();
        genesisRepository.saveAndFlush(AccountGenesisRecord.attachedBootstrap(genesis.accountId().value(), USER,
                (short) genesis.version(), (short) genesis.suite(),
                Base64.getUrlEncoder().withoutPadding().encodeToString(genesis.canonicalBytes()), clock.instant()));
        reference = genesis.accountId().rawBytes();
    }

    @AfterEach
    void tearDown() throws IOException {
        resolver.shutdown();
        publicationRepository.deleteAll();
        headRepository.deleteAll();
        recordRepository.deleteAll();
        deviceRepository.deleteAll();
        challengeRepository.deleteAll();
        candidateRepository.deleteAll();
        genesisRepository.deleteAll();
    }

    /** Rebuilt after a flag change, because the client reads its base URL once, as the container does. */
    private void rebuildService() {
        UserSecurityService userSecurityService = mock(UserSecurityService.class);
        AuthorityPolicy policy = new AuthorityPolicy(properties, userSecurityService);
        AuthorityAccounts accounts = new AuthorityAccounts(genesisRepository);
        challenges = new AuthorityChallengeService(challengeRepository, policy,
                new AuthorityChallengeBurn(challengeRepository));
        service = new AccountAuthorityService(policy, accounts, challenges,
                mock(AuthorityStepUpService.class), headRepository, recordRepository, deviceRepository,
                candidateRepository, new AuthorityNotifications(List.of(new StubChannel())),
                new NoBackoff(policy),
                AuthorityHeadPublisherFixtures.real(properties, publicationRepository, publications, clock),
                new LoggingSecurityAuditLogger(), clock);
    }

    // --- Publishing on the transitions that move the head ---------------------

    @Test
    void nothingIsPublishedWhileTheRecordIsStillInsideItsWindow() {
        enablePublishing();

        adopt();

        // The head row names the pending AdoptRoot at seq 1 while it holds its slot, and an opposition can
        // still cancel it. The log is append-only, so that hash must not reach it.
        assertThat(head().getHeadSeq()).isEqualTo(1L);
        assertThat(head().hasPending()).isTrue();
        assertThat(resolver.getRequestCount()).isZero();
        assertThat(publicationRepository.findByAccount(account())).isEmpty();
    }

    @Test
    void theSettledHeadIsPublishedWhenTheWindowCompletes() throws Exception {
        enablePublishing();
        adopt();

        clock.advance(Duration.ofHours(73));
        readState();

        assertThat(resolver.getRequestCount()).isEqualTo(1);
        RecordedRequest request = resolver.takeRequest();
        assertThat(request.getMethod()).isEqualTo("POST");
        assertThat(request.getPath()).isEqualTo("/account/authority/heads");

        AuthorityHeadRecord published = publishedIn(request);
        assertThat(published.accountReference()).isEqualTo(reference);
        assertThat(published.headSeq()).isEqualTo(1L);
        assertThat(published.headHashHex()).isEqualTo(head().getHeadHash());
        assertThat(published.homeserverId()).isEqualTo(FEDERATION_ID);
        assertThat(published.issuedAt()).isEqualTo(clock.instant());
        assertThat(published.notAfter()).isEqualTo(clock.instant().plus(Duration.ofDays(400)));

        AuthorityHeadPublication row = publicationRepository.findByAccount(account()).orElseThrow();
        assertThat(row.getHeadSeq()).isEqualTo(1L);
        assertThat(row.getPayloadHash()).isEqualTo(published.payloadHashHex());
        assertThat(row.isConfirmed()).isTrue();
        assertThat(row.getAttempts()).isEqualTo(1);
        assertThat(row.getLastAttemptAt()).isEqualTo(clock.instant());
    }

    @Test
    void theEnvelopeIsSignedUnderTheHomeserversRosterMembershipKey() throws Exception {
        enablePublishing();
        rootTheAccount();

        RecordedRequest request = resolver.takeRequest();
        JsonNode envelope = JSON.readTree(request.getBody().readUtf8());
        byte[] canonical = Base64.getUrlDecoder().decode(envelope.path("record").asText());
        byte[] signature = Base64.getDecoder().decode(envelope.path("signature").asText());

        // The resolver verifies exactly this: the named homeserver's entry in a roster it has verified
        // k-of-n, ACTIVE at acceptance time, and the signature under that entry's published key.
        assertThat(Ed25519Keys.verify(membershipKey.rawPublicKey(),
                AuthorityHeadRecordCodec.signaturePreimage(canonical), signature)).isTrue();
        assertThat(envelope.path("record").asText())
                .isEqualTo(Base64.getUrlEncoder().withoutPadding().encodeToString(canonical));
    }

    @Test
    void anImmediateTransitionPublishesItsOwnHeadWithoutWaiting() throws Exception {
        enablePublishing();
        rootTheAccount();
        resolver.takeRequest();

        // A grant only adds and its holder is quarantined, so it takes effect immediately: the settled head
        // moves inside the submitting request rather than at the end of a window.
        grantSecondDevice();

        assertThat(resolver.getRequestCount()).isEqualTo(2);
        AuthorityHeadRecord published = publishedIn(resolver.takeRequest());
        assertThat(published.headSeq()).isEqualTo(2L);
        assertThat(published.headHashHex()).isEqualTo(head().getHeadHash());
    }

    @Test
    void aCancelledRecordNeverReachesTheLogAndThePublishedHeadDoesNotGoBackwards() throws Exception {
        enablePublishing();
        rootTheAccount();
        resolver.takeRequest();
        grantSecondDevice();
        resolver.takeRequest();

        // Two heads are in the log by now, one per settled transition, and the count below is cumulative.
        assertThat(resolver.getRequestCount()).isEqualTo(2);

        String pendingHash = revokeSecondDevice().recordHash();
        assertThat(head().getHeadSeq()).isEqualTo(3L);
        assertThat(resolver.getRequestCount()).isEqualTo(2);

        // Opposed by the first device, which is the account's only unquarantined key: a device granted a
        // moment ago is still serving its quarantine and may not authorize anything yet.
        opposeAs(firstDevice, pendingHash);

        // The cancellation gave the slot back and rolled the head to seq 2, which is already published. There
        // is nothing to retract and nothing new to say.
        assertThat(head().getHeadSeq()).isEqualTo(2L);
        assertThat(recordRepository.findByAccountAndSeq(account(), 3L).orElseThrow().getState())
                .isEqualTo(AuthorityChainRecord.State.CANCELLED);
        assertThat(resolver.getRequestCount()).isEqualTo(2);
        assertThat(publicationRepository.findByAccount(account()).orElseThrow().getHeadSeq()).isEqualTo(2L);
    }

    // --- Idempotency ----------------------------------------------------------

    @Test
    void aSecondPassOverAnAlreadyPublishedHeadSendsNothing() {
        enablePublishing();
        rootTheAccount();
        assertThat(resolver.getRequestCount()).isEqualTo(1);

        readState();
        readState();
        readState();

        // The catch-up runs on every pass over the account, which is what makes a failed delivery recover
        // without a scheduler. A head already in the log is where it lands, and it must cost nothing: the log's
        // size is the roster version, so one leaf per read would move where new accounts are placed.
        assertThat(resolver.getRequestCount()).isEqualTo(1);
    }

    @Test
    void anUnacknowledgedHeadIsRetriedWithByteIdenticalBytes() throws Exception {
        properties.getAuthority().getPublication().setEnabled(true);
        resolver.enqueue(new MockResponse().setResponseCode(503));
        resolver.enqueue(new MockResponse().setResponseCode(200));
        rebuildService();

        rootTheAccount();
        String first = bodyOf(resolver.takeRequest());
        assertThat(publicationRepository.findByAccount(account()).orElseThrow().isConfirmed()).isFalse();

        // Inside the retry floor nothing is resent, because this catch-up runs on the same reads the account
        // holder's own client makes and an unreachable resolver must not put a socket timeout in front of them.
        readState();
        assertThat(resolver.getRequestCount()).isEqualTo(1);

        clock.advance(Duration.ofMinutes(6));
        readState();

        assertThat(resolver.getRequestCount()).isEqualTo(2);
        String retry = bodyOf(resolver.takeRequest());

        // Byte-identical, because the retry resends the stored bytes rather than signing a second head. That
        // is the whole of the idempotency claim: the same bytes hash to the same payload, so the leaf the
        // retry commits is the leaf the first attempt would have committed.
        assertThat(retry).isEqualTo(first);

        AuthorityHeadPublication row = publicationRepository.findByAccount(account()).orElseThrow();
        assertThat(row.isConfirmed()).isTrue();
        assertThat(row.getAttempts()).isEqualTo(2);
        assertThat(row.getLastAttemptAt()).isEqualTo(clock.instant());
    }

    @Test
    void aConflictFromTheResolverCountsAsPublishedRatherThanRetriedForever() throws Exception {
        properties.getAuthority().getPublication().setEnabled(true);
        resolver.enqueue(new MockResponse().setResponseCode(409));
        rebuildService();

        rootTheAccount();
        resolver.takeRequest();

        // The resolver already holds this head, which is not an error: the log is append-only and a head
        // already committed needs no second leaf.
        assertThat(publicationRepository.findByAccount(account()).orElseThrow().isConfirmed()).isTrue();
        readState();
        assertThat(resolver.getRequestCount()).isEqualTo(1);
    }

    @Test
    void anAgingHeadIsReIssuedOnceTheRepublishIntervalHasPassed() throws Exception {
        enablePublishing();
        rootTheAccount();
        String first = bodyOf(resolver.takeRequest());

        clock.advance(Duration.ofDays(301));
        readState();

        assertThat(resolver.getRequestCount()).isEqualTo(2);
        String reissued = bodyOf(resolver.takeRequest());
        assertThat(reissued).isNotEqualTo(first);

        AuthorityHeadRecord published = publishedIn(reissued);
        // The same head, a fresh window. An account with no transitions for years would otherwise go stale in
        // the client, and a stale attestation reads as unverified rather than as verified.
        assertThat(published.headSeq()).isEqualTo(1L);
        assertThat(published.issuedAt()).isEqualTo(clock.instant());

        readState();
        assertThat(resolver.getRequestCount()).isEqualTo(2);
    }

    // --- The flag -------------------------------------------------------------

    @Test
    void withPublishingOffNothingIsSignedAndNothingIsSent() {
        assertThat(properties.getAuthority().getPublication().isEnabled()).isFalse();

        rootTheAccount();
        grantSecondDevice();
        readState();

        // The chain ran every transition. Nothing was signed, no row was written, and the resolver socket was
        // never touched: the two flags are two decisions, and this is the state the first one leaves.
        assertThat(head().getHeadSeq()).isEqualTo(2L);
        assertThat(deviceRepository.findByAccount(account())).hasSize(2);
        assertThat(resolver.getRequestCount()).isZero();
        assertThat(publicationRepository.findByAccount(account())).isEmpty();
    }

    @Test
    void publishingCanBeTurnedOnLaterAndPicksUpTheHeadTheChainAlreadyHas() throws Exception {
        rootTheAccount();
        grantSecondDevice();
        assertThat(resolver.getRequestCount()).isZero();

        enablePublishing();
        readState();

        // Turning the flag on does not need a backfill job: the first pass over the account publishes the head
        // it already has, on the same lazy path settlement runs on.
        assertThat(resolver.getRequestCount()).isEqualTo(1);
        assertThat(publishedIn(resolver.takeRequest()).headSeq()).isEqualTo(2L);
    }

    @Test
    void aResolverThatCannotBeReachedDoesNotFailTheTransition() {
        properties.getAuthority().getPublication().setEnabled(true);
        properties.getAuthority().getPublication().setResolverBaseUrl("http://127.0.0.1:1");
        rebuildService();

        rootTheAccount();

        // A head that reaches the log late is a delay. A transition refused because federation state was
        // unreachable would be an outage, and adoption would be the first thing to fall over.
        assertThat(head().getHeadSeq()).isEqualTo(1L);
        assertThat(deviceRepository.findByAccount(account())).hasSize(1);
        assertThat(publicationRepository.findByAccount(account()).orElseThrow().isConfirmed()).isFalse();
    }

    // --- Helpers --------------------------------------------------------------

    private void enablePublishing() {
        properties.getAuthority().getPublication().setEnabled(true);
        resolver.setDispatcher(new okhttp3.mockwebserver.Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return new MockResponse().setResponseCode(200);
            }
        });
        rebuildService();
    }

    /** The body, read once: {@code RecordedRequest.getBody()} is a buffer and a second read finds it empty. */
    private static String bodyOf(RecordedRequest request) {
        return request.getBody().readUtf8();
    }

    private static AuthorityHeadRecord publishedIn(String body) throws Exception {
        JsonNode envelope = JSON.readTree(body);
        return AuthorityHeadRecordCodec.decode(
                Base64.getUrlDecoder().decode(envelope.path("record").asText()));
    }

    private static AuthorityHeadRecord publishedIn(RecordedRequest request) throws Exception {
        return publishedIn(bodyOf(request));
    }

    /**
     * Runs one service call in its own transaction, the way the container's proxy would.
     *
     * <p>The service is built with {@code new} here rather than injected, so nothing applies its
     * {@code @Transactional}, and this class deliberately does not run inside one of its own. One transaction
     * per call is also what the publication is about: the delivery is registered to fire when that transaction
     * commits, and a test sharing one long transaction with the code under test would never see it.
     */
    private <T> T call(java.util.function.Supplier<T> action) {
        return transactions.execute(status -> action.get());
    }

    private void adopt() {
        String challenge = mint(Purpose.ADOPT);
        byte[] bytes = AuthorityRecords.adoptRootFor(reference, firstDevice.rawPublicKey(),
                recoveryKey.rawPublicKey(), "iPhone", 1, AuthorityRecord.emptyPrevHash());
        call(() -> service.adopt(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.ADOPT_ROOT, challenge, bytes), challenge, true));
    }

    private void readState() {
        call(() -> service.state(USER));
    }

    private void rootTheAccount() {
        adopt();
        clock.advance(Duration.ofHours(73));
        readState();
    }

    private void grantSecondDevice() {
        call(() -> service.registerCandidate(USER, encode(secondDevice.rawPublicKey()), "iPad"));
        String challenge = mint(Purpose.GRANT);
        byte[] bytes = AuthorityRecords.grantFor(reference, secondDevice.rawPublicKey(),
                firstDevice.rawPublicKey(), "iPad", head().nextSeq(), hexToBytes(head().getHeadHash()));
        call(() -> service.grantDevice(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.DEVICE_GRANT, challenge, bytes), challenge));
    }

    private AccountAuthorityService.Submitted revokeSecondDevice() {
        String challenge = mint(Purpose.REVOKE);
        byte[] bytes = AuthorityRecords.revokeFor(reference, secondDevice.rawPublicKey(),
                firstDevice.rawPublicKey(), AuthorityRecord.REASON_UNSPECIFIED, head().nextSeq(),
                hexToBytes(head().getHeadHash()));
        return call(() -> service.revokeDevice(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                sign(firstDevice, AuthorityRecordType.DEVICE_REVOKE, challenge, bytes), challenge));
    }

    private void opposeAs(TestEd25519.Pair signer, String opposedRecordHash) {
        String challenge = mint(Purpose.OPPOSE);
        AuthorityChainRecord pending = recordRepository
                .findByAccountAndRecordHash(account(), opposedRecordHash).orElseThrow();
        byte[] bytes = AuthorityRecords.opposeFor(reference, hexToBytes(opposedRecordHash),
                signer.rawPublicKey(), pending.getSeq(), hexToBytes(pending.getPrevHash()));
        call(() -> {
            service.opposeWithRecord(USER, Optional.of(NATIVE_CLIENT), SESSION, encode(bytes),
                    sign(signer, AuthorityRecordType.OPPOSE, challenge, bytes), challenge);
            return null;
        });
    }

    /**
     * Minted in a transaction of its own, because this class runs outside one: the challenge store sweeps
     * expired rows on the way in, and a bulk delete needs a transaction to sit in.
     */
    private String mint(Purpose purpose) {
        return transactions.execute(status -> challenges.mint(account(), SESSION, purpose, AuthFactor.PASSKEY,
                clock.instant().minus(Duration.ofDays(30)), clock.instant()).challenge());
    }

    private String account() {
        return genesisRepository.findByUserId(USER).orElseThrow().getAccountId();
    }

    private AuthorityChainHead head() {
        return headRepository.findByAccount(account()).orElseThrow();
    }

    private static String sign(TestEd25519.Pair pair, AuthorityRecordType type, String challengeB64,
            byte[] bytes) {
        byte[] challenge = Base64.getUrlDecoder().decode(challengeB64);
        return encode(TestEd25519.sign(pair.privateKey(),
                AuthorityProofs.recordPreimage(type, challenge, bytes)));
    }

    private static String encode(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static byte[] hexToBytes(String hex) {
        return java.util.HexFormat.of().parseHex(hex);
    }

    /** A clock a test can walk forward, so a 72-hour window does not need 72 hours. */
    private static final class MutableClock extends Clock {

        private Instant now;

        private MutableClock(Instant now) {
            this.now = now;
        }

        private void advance(Duration by) {
            now = now.plus(by);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /**
     * A channel that reaches the account holder, so gate 2 does not refuse every transition this class walks.
     * What a notification says has its own tests.
     */
    private static final class StubChannel implements AuthorityNotifier {

        @Override
        public boolean isOutOfBand() {
            return true;
        }

        @Override
        public boolean reachesOutOfBand(String userId) {
            return true;
        }

        @Override
        public void notifyTransitionPending(String userId, String transition, String deviceLabel,
                Instant effectiveAt) {
        }

        @Override
        public void notifyTransitionCancelled(String userId, String transition, String deviceLabel) {
        }

        @Override
        public void notifyTransitionCompleted(String userId, String transition, String deviceLabel) {
        }
    }

    /** No doubling, so a test walking several transitions is not refused by a budget it is not about. */
    private static final class NoBackoff extends AuthorityBackoff {

        private NoBackoff(AuthorityPolicy policy) {
            super(null, policy);
        }

        @Override
        public Optional<Instant> until(String account, String keyB64) {
            return Optional.empty();
        }

        @Override
        public Instant recordCancellation(String account, String keyB64, Instant now) {
            // The doubling has its own unit test; a test walking several transitions must not be refused by a
            // budget it is not about.
            return now;
        }
    }
}
