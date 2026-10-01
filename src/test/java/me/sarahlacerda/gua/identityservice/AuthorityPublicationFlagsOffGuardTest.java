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

class AuthorityPublicationFlagsOffGuardTest {

    private static final Path MAIN_SOURCES = Path.of("src", "main", "java");

    private final IdentityServiceProperties untouched = new IdentityServiceProperties();

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
    void publicationIsASeparateSwitchFromTheChainItself() {
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
