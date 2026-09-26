// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityHeadRecordCodec;
import me.sarahlacerda.gua.identityservice.account.genesis.TestEd25519;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.PublicationProperties;
import me.sarahlacerda.gua.identityservice.domain.AuthorityChainHead;
import me.sarahlacerda.gua.identityservice.repository.AuthorityHeadPublicationRepository;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityAccounts;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityHeadPublications;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityHeadPublisher;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityHeadSigner;
import me.sarahlacerda.gua.identityservice.service.authority.AuthorityPublicationStartupCheck;
import me.sarahlacerda.gua.identityservice.service.authority.ResolverAuthorityHeadClient;
import me.sarahlacerda.gua.identityservice.service.placement.FederationIds;
import me.sarahlacerda.gua.identityservice.service.placement.RosterMembershipKeys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Publishing the chain head is behind its own flag, that flag defaults to false, and with it off this service
 * behaves exactly as it did before the publication existed (ADM-009 decision 12).
 *
 * <p>"Its own flag" is the point of this class rather than a detail. Decision 12's gap is real and turning the
 * chain on is already a decision with gates of its own; writing an account's head into federation state is a
 * second one, and a deployment has to be able to run the chain for as long as it takes to validate it while
 * nothing has been published. So there are two switches, and the second one is the one this class is about.
 *
 * <p>The counterpart is that turning it on must not half-work. A publication path that quietly skips every head
 * because a homeserver id was never set would make the gap look closed from the outside, so the last half of
 * this class is every way that misconfiguration is refused at startup instead.
 */
class AuthorityPublicationFlagsOffGuardTest {

    private static final Path MAIN_SOURCES = Path.of("src", "main", "java");

    private final IdentityServiceProperties untouched = new IdentityServiceProperties();

    // --- Off by default ------------------------------------------------------

    @Test
    void everyPublicationFlagDefaultsToOff() {
        PublicationProperties publication = untouched.getAuthority().getPublication();

        assertThat(publication.isEnabled()).isFalse();
        assertThat(publication.getResolverBaseUrl()).isEmpty();
        assertThat(publication.getHomeserverId()).isEmpty();
        assertThat(publication.getHeadValidity()).isEqualTo(Duration.ofDays(400));
        assertThat(publication.getRepublishAfter()).isEqualTo(Duration.ofDays(300));
        assertThat(publication.getRetryAfter()).isEqualTo(Duration.ofMinutes(5));
    }

    @Test
    void itIsASeparateSwitchFromTheChainItself() {
        // Two flags, two decisions. Turning the chain on must not start writing to federation state, which is
        // what one flag for both would have meant.
        untouched.getAuthority().setEnabled(true);

        assertThat(untouched.getAuthority().getPublication().isEnabled()).isFalse();
    }

    @Test
    void theShippedConfigurationTurnsThePublicationOff() throws IOException {
        String yaml = Files.readString(Path.of("src", "main", "resources", "application.yml"));

        assertThat(yaml).contains("IDENTITY_AUTHORITY_PUBLICATION_ENABLED:false");
        assertThat(yaml).contains("IDENTITY_AUTHORITY_PUBLICATION_RESOLVER_BASE_URL:}");
        assertThat(yaml).contains("IDENTITY_AUTHORITY_PUBLICATION_HOMESERVER_ID:}");
        assertThat(yaml).contains("IDENTITY_AUTHORITY_PUBLICATION_HEAD_VALIDITY:P400D");
        assertThat(yaml).contains("IDENTITY_AUTHORITY_PUBLICATION_REPUBLISH_AFTER:P300D");
        assertThat(yaml).contains("IDENTITY_AUTHORITY_PUBLICATION_RETRY_AFTER:PT5M");
    }

    // --- With the flag off, nothing happens ----------------------------------

    @Test
    void withTheFlagOffThePublisherTouchesNothing() {
        AuthorityHeadPublicationRepository repository = mock(AuthorityHeadPublicationRepository.class);
        AuthorityHeadSigner signer = mock(AuthorityHeadSigner.class);
        ResolverAuthorityHeadClient resolver = mock(ResolverAuthorityHeadClient.class);
        AuthorityHeadPublications publications = mock(AuthorityHeadPublications.class);
        AuthorityHeadPublisher publisher = new AuthorityHeadPublisher(untouched, repository, signer, resolver,
                publications, Clock.systemUTC());

        assertThat(publisher.isEnabled()).isFalse();
        publisher.publishSettledHead(account(), settledHead(), Clock.systemUTC().instant());

        // No row read, nothing signed, nothing sent, and no acknowledgement written. The flag is checked
        // before any collaborator is consulted, which is what makes "the chain runs unpublished" literal.
        verifyNoInteractions(repository);
        verifyNoInteractions(signer);
        verifyNoInteractions(resolver);
        verifyNoInteractions(publications);
    }

    @Test
    void withNoResolverConfiguredTheClientIsInertAndBuildsNoHttpClient() {
        ResolverAuthorityHeadClient client = new ResolverAuthorityHeadClient(WebClient.builder(), untouched);

        assertThat(client.isConfigured()).isFalse();
        assertThat(client.publish("anything", "anything"))
                .isEqualTo(ResolverAuthorityHeadClient.PublishOutcome.UNAVAILABLE);
        assertThat(client.publish(null, null))
                .isEqualTo(ResolverAuthorityHeadClient.PublishOutcome.UNAVAILABLE);
    }

    @Test
    void withNoHomeserverConfiguredNothingCanBeSigned() {
        AuthorityHeadSigner signer = signer(untouched);

        assertThat(signer.homeserverId()).isEmpty();
        assertThat(signer.canSign()).isFalse();
    }

    @Test
    void aMalformedMembershipKeyDoesNotStopADeploymentWithPublishingOffFromStarting() {
        IdentityServiceProperties off = publishing();
        off.getAuthority().getPublication().setEnabled(false);
        off.getRouting().getHomeservers().get(0).setPlacementSigningPrivateKey("this is not a key");

        // The key is parsed on first use, so a deployment that will never sign is not refused for holding a
        // key it will never read. A deployment that does publish has it decoded at startup instead.
        assertThatCode(() -> signer(off)).doesNotThrowAnyException();
        assertThatCode(() -> new AuthorityPublicationStartupCheck(off, signer(off),
                new ResolverAuthorityHeadClient(WebClient.builder(), off)).verifyAuthorityPublication())
                .doesNotThrowAnyException();
    }

    @Test
    void withThePublicationOffTheStartupCheckReadsNothing() {
        ResolverAuthorityHeadClient resolver = mock(ResolverAuthorityHeadClient.class);
        AuthorityHeadSigner signer = mock(AuthorityHeadSigner.class);

        new AuthorityPublicationStartupCheck(untouched, signer, resolver).verifyAuthorityPublication();

        verifyNoInteractions(resolver);
        verifyNoInteractions(signer);
    }

    @Test
    void thePublicationStartsNoSchedulerAndNoPeriodicJob() throws IOException {
        // Heads are published on the transitions that move them, on the same lazy path settlement already runs
        // on. A scheduler started for this one sweep would start one for everything else, which is the choice
        // the placement comparison had to make a flag for.
        List<String> offenders = new ArrayList<>();
        for (Path file : authoritySources()) {
            for (String line : codeLines(file)) {
                if (line.contains("@Scheduled") || line.contains("@EnableScheduling")) {
                    offenders.add(file.getFileName() + ": " + line);
                }
            }
        }

        assertThat(offenders).isEmpty();
    }

    // --- Turning it on without its prerequisites is refused ------------------

    @Test
    void publishingWithoutTheChainIsRefusedAtStartup() {
        IdentityServiceProperties properties = publishing();
        properties.getAuthority().setEnabled(false);

        assertThatThrownBy(() -> check(properties).verifyAuthorityPublication())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("identity.authority.enabled is off");
    }

    @Test
    void publishingWithoutAHomeserverIdIsRefusedAtStartup() {
        IdentityServiceProperties properties = publishing();
        properties.getAuthority().getPublication().setHomeserverId("");

        assertThatThrownBy(() -> check(properties).verifyAuthorityPublication())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("homeserver-id is not set");
    }

    @Test
    void publishingUnderAHomeserverThisDeploymentHoldsNoKeyForIsRefusedAtStartup() {
        IdentityServiceProperties properties = publishing();
        properties.getAuthority().getPublication().setHomeserverId("hs-somebody-else");

        // The signed object names a roster identity and the resolver verifies it under that entry's published
        // key. Naming a homeserver whose key this deployment does not hold would produce heads nobody accepts.
        assertThatThrownBy(() -> check(properties).verifyAuthorityPublication())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("hs-somebody-else");
    }

    @Test
    void publishingWithNoResolverIsRefusedAtStartup() {
        IdentityServiceProperties properties = publishing();
        properties.getAuthority().getPublication().setResolverBaseUrl("");

        assertThatThrownBy(() -> check(properties).verifyAuthorityPublication())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("resolver-base-url is not set");
    }

    @Test
    void aMalformedMembershipKeyIsRefusedAtStartupWhenPublishingIsOn() {
        IdentityServiceProperties properties = publishing();
        properties.getRouting().getHomeservers().get(0).setPlacementSigningPrivateKey("this is not a key");

        assertThatThrownBy(() -> check(properties).verifyAuthorityPublication())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not a readable Ed25519 private key");
    }

    @Test
    void aWindowTheCodecWouldRefuseIsRefusedAtStartupInstead() {
        IdentityServiceProperties properties = publishing();
        properties.getAuthority().getPublication().setHeadValidity(Duration.ofDays(401));

        // Accepted at boot, this throws on every single head, which surfaces as a publication path that does
        // nothing rather than as the misconfiguration it is.
        assertThatThrownBy(() -> check(properties).verifyAuthorityPublication())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(AuthorityHeadRecordCodec.MAX_VALIDITY.toDays() + " days");

        IdentityServiceProperties zero = publishing();
        zero.getAuthority().getPublication().setHeadValidity(Duration.ZERO);
        assertThatThrownBy(() -> check(zero).verifyAuthorityPublication())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aReIssueIntervalThatWouldNeverFireOrWouldFireAlwaysIsRefusedAtStartup() {
        IdentityServiceProperties tooLate = publishing();
        tooLate.getAuthority().getPublication().setRepublishAfter(Duration.ofDays(400));
        assertThatThrownBy(() -> check(tooLate).verifyAuthorityPublication())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not shorter than head-validity");

        IdentityServiceProperties always = publishing();
        always.getAuthority().getPublication().setRepublishAfter(Duration.ZERO);
        assertThatThrownBy(() -> check(always).verifyAuthorityPublication())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("once per read");
    }

    @Test
    void aRetryFloorThatIsNotAWaitIsRefusedAtStartup() {
        IdentityServiceProperties properties = publishing();
        properties.getAuthority().getPublication().setRetryAfter(Duration.ofMinutes(-1));

        assertThatThrownBy(() -> check(properties).verifyAuthorityPublication())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("retry-after");
    }

    @Test
    void aFullyConfiguredDeploymentStarts() {
        assertThatCode(() -> check(publishing()).verifyAuthorityPublication()).doesNotThrowAnyException();
    }

    // --- Helpers -------------------------------------------------------------

    private static IdentityServiceProperties publishing() {
        IdentityServiceProperties properties = new IdentityServiceProperties();
        TestEd25519.Pair pair = TestEd25519.generate();
        HomeserverConfig homeserver = new HomeserverConfig();
        homeserver.setId("primary");
        homeserver.setDomain("example.test");
        homeserver.setAdminApiBaseUrl("http://admin.invalid");
        homeserver.setClientApiBaseUrl("http://client.invalid");
        homeserver.setAdminAccessToken("not-a-real-token");
        homeserver.setFederationId("hs-alpha");
        homeserver.setPlacementSigningPrivateKey(
                Base64.getEncoder().encodeToString(pair.privateKey().getEncoded()));
        properties.getRouting().getHomeservers().add(homeserver);
        properties.getAuthority().setEnabled(true);
        properties.getAuthority().getPublication().setEnabled(true);
        properties.getAuthority().getPublication().setHomeserverId("hs-alpha");
        properties.getAuthority().getPublication().setResolverBaseUrl("http://resolver.invalid");
        return properties;
    }

    private static AuthorityHeadSigner signer(IdentityServiceProperties properties) {
        return new AuthorityHeadSigner(properties,
                new RosterMembershipKeys(properties, new FederationIds(properties)));
    }

    private static AuthorityPublicationStartupCheck check(IdentityServiceProperties properties) {
        return new AuthorityPublicationStartupCheck(properties, signer(properties),
                new ResolverAuthorityHeadClient(WebClient.builder(), properties));
    }

    private static AuthorityAccounts.Resolved account() {
        return new AuthorityAccounts.Resolved("@sarah:example.test", "ga1" + "a".repeat(55), new byte[34],
                (byte) 0x00, false, null, null);
    }

    private static AuthorityChainHead settledHead() {
        AuthorityChainHead head = AuthorityChainHead.empty("ga1" + "a".repeat(55), java.time.Instant.EPOCH);
        head.setHeadSeq(1L);
        head.setHeadHash("11".repeat(32));
        return head;
    }

    private static List<Path> authoritySources() throws IOException {
        Path base = MAIN_SOURCES.resolve("me/sarahlacerda/gua/identityservice");
        try (Stream<Path> paths = Files.walk(base.resolve("service/authority"))) {
            List<Path> files = new ArrayList<>(paths.filter(path -> path.toString().endsWith(".java")).toList());
            try (Stream<Path> codec = Files.walk(base.resolve("account/authority"))) {
                files.addAll(codec.filter(path -> path.toString().endsWith(".java")).toList());
            }
            return files;
        }
    }

    private static List<String> codeLines(Path file) throws IOException {
        List<String> lines = new ArrayList<>();
        for (String raw : Files.readAllLines(file)) {
            String line = raw.replaceAll("\\s//.*$", "").trim();
            if (line.isEmpty() || line.startsWith("//") || line.startsWith("*") || line.startsWith("/*")) {
                continue;
            }
            lines.add(line);
        }
        return lines;
    }
}
