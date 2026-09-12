// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.placement;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.account.genesis.TestEd25519;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.service.placement.ResolverPlacementClient.HomeserverView;
import me.sarahlacerda.gua.identityservice.service.placement.ResolverPlacementClient.RosterEntryView;
import me.sarahlacerda.gua.identityservice.service.placement.ResolverPlacementClient.RosterView;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The startup consistency check: a deployment may not publish placement records under an identity the
 * roster does not agree with.
 *
 * <p>Each case here is a way the three things could fail to line up. Together they are what stops this
 * service signing records for a homeserver it is not, or with a key nobody will verify against.
 */
class PlacementSignerStartupCheckTest {

    private final TestEd25519.Pair pair = PlacementTestFixtures.keyPair();
    private final ResolverPlacementClient resolver = mock(ResolverPlacementClient.class);

    private IdentityServiceProperties publishing() {
        IdentityServiceProperties properties = PlacementTestFixtures.propertiesWithOneHomeserver(pair);
        properties.getPlacement().getPublish().setEnabled(true);
        return properties;
    }

    private PlacementSignerStartupCheck check(IdentityServiceProperties properties) {
        return new PlacementSignerStartupCheck(properties, resolver, new PlacementRecordSigner(properties));
    }

    private RosterView rosterWith(String id, String serverName, String signingKey, String status) {
        return new RosterView(7, List.of(new RosterEntryView(
                new HomeserverView(id, serverName, signingKey), status)));
    }

    private void rosterIsAvailable(RosterView roster) {
        when(resolver.isConfigured()).thenReturn(true);
        when(resolver.fetchRoster()).thenReturn(Optional.of(roster));
    }

    @Test
    void aMatchingRosterEntryPassesTheCheck() {
        rosterIsAvailable(rosterWith(PlacementTestFixtures.FEDERATION_ID, PlacementTestFixtures.DOMAIN,
                PlacementTestFixtures.publicKeyBase64(pair), "ACTIVE"));

        assertThatCode(() -> check(publishing()).verifyPlacementSigningIdentity()).doesNotThrowAnyException();
    }

    @Test
    void anX509SpellingOfTheSameKeyAlsoPasses() {
        // The roster may publish the bare key or the X.509 wrapper; a check that understood one spelling
        // would report a mismatch that is not there.
        String spki = java.util.Base64.getEncoder()
                .encodeToString(hexToBytes("302a300506032b6570032100") == null ? new byte[0] : concat(
                        hexToBytes("302a300506032b6570032100"), pair.rawPublicKey()));
        rosterIsAvailable(rosterWith(PlacementTestFixtures.FEDERATION_ID, PlacementTestFixtures.DOMAIN, spki,
                "ACTIVE"));

        assertThatCode(() -> check(publishing()).verifyPlacementSigningIdentity()).doesNotThrowAnyException();
    }

    @Test
    void withPublishingOffNothingIsCheckedAndTheRosterIsNotEvenRead() {
        IdentityServiceProperties properties = PlacementTestFixtures.propertiesWithOneHomeserver(pair);

        assertThatCode(() -> check(properties).verifyPlacementSigningIdentity()).doesNotThrowAnyException();

        verifyNoInteractions(resolver);
    }

    @Test
    void theLegacySynthesisedHomeserverCannotPublish() {
        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getPlacement().getPublish().setEnabled(true);

        // It has no roster identity, so there is no id a record could name and no key to sign one with.
        assertThatThrownBy(() -> check(properties).verifyPlacementSigningIdentity())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("identity.routing.homeservers");
    }

    @Test
    void anUnreachableRosterStopsStartupRatherThanBeingAssumedFine() {
        when(resolver.isConfigured()).thenReturn(true);
        when(resolver.fetchRoster()).thenReturn(Optional.empty());

        assertThatThrownBy(() -> check(publishing()).verifyPlacementSigningIdentity())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("roster could not be read");
    }

    @Test
    void noResolverBaseUrlStopsStartup() {
        IdentityServiceProperties properties = publishing();
        properties.getPlacement().setResolverBaseUrl("");
        when(resolver.isConfigured()).thenReturn(false);

        assertThatThrownBy(() -> check(properties).verifyPlacementSigningIdentity())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("resolver-base-url");
    }

    @Test
    void aDomainThatMatchesNoRosterEntryStopsStartup() {
        rosterIsAvailable(rosterWith(PlacementTestFixtures.FEDERATION_ID, "somewhere.example.test",
                PlacementTestFixtures.publicKeyBase64(pair), "ACTIVE"));

        assertThatThrownBy(() -> check(publishing()).verifyPlacementSigningIdentity())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("matches no federation roster entry");
    }

    @Test
    void anEntryThatIsNotActiveStopsStartup() {
        rosterIsAvailable(rosterWith(PlacementTestFixtures.FEDERATION_ID, PlacementTestFixtures.DOMAIN,
                PlacementTestFixtures.publicKeyBase64(pair), "SUSPENDED"));

        assertThatThrownBy(() -> check(publishing()).verifyPlacementSigningIdentity())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("rather than ACTIVE");
    }

    @Test
    void aFederationIdThatIsNotTheRosterIdStopsStartup() {
        rosterIsAvailable(rosterWith("fed-somebody-else", PlacementTestFixtures.DOMAIN,
                PlacementTestFixtures.publicKeyBase64(pair), "ACTIVE"));

        assertThatThrownBy(() -> check(publishing()).verifyPlacementSigningIdentity())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("is not the roster id");
    }

    @Test
    void aSigningKeyThatIsNotThePrivateHalfOfTheRosterKeyStopsStartup() {
        TestEd25519.Pair other = PlacementTestFixtures.keyPair();
        rosterIsAvailable(rosterWith(PlacementTestFixtures.FEDERATION_ID, PlacementTestFixtures.DOMAIN,
                PlacementTestFixtures.publicKeyBase64(other), "ACTIVE"));

        assertThatThrownBy(() -> check(publishing()).verifyPlacementSigningIdentity())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not the private half");
    }

    @Test
    void publishingWithNoSigningKeyAnywhereStopsStartup() {
        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getPlacement().setResolverBaseUrl("http://resolver.invalid");
        properties.getPlacement().getPublish().setEnabled(true);
        properties.getRouting().getHomeservers().add(PlacementTestFixtures.homeserver(
                PlacementTestFixtures.LOCAL_ID, PlacementTestFixtures.DOMAIN,
                PlacementTestFixtures.FEDERATION_ID, ""));
        rosterIsAvailable(rosterWith(PlacementTestFixtures.FEDERATION_ID, PlacementTestFixtures.DOMAIN,
                PlacementTestFixtures.publicKeyBase64(pair), "ACTIVE"));

        assertThatThrownBy(() -> check(properties).verifyPlacementSigningIdentity())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("no configured homeserver carries a placement signing key");
    }

    @Test
    void theFailureMessageNamesTheHomeserverByItsConfiguredIdOnly() {
        rosterIsAvailable(rosterWith("fed-somebody-else", PlacementTestFixtures.DOMAIN,
                PlacementTestFixtures.publicKeyBase64(pair), "ACTIVE"));

        assertThatThrownBy(() -> check(publishing()).verifyPlacementSigningIdentity())
                .hasMessageContaining(PlacementTestFixtures.LOCAL_ID)
                .hasMessageNotContaining(PlacementTestFixtures.DOMAIN);
    }

    private static byte[] hexToBytes(String hex) {
        return java.util.HexFormat.of().parseHex(hex);
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] out = new byte[first.length + second.length];
        System.arraycopy(first, 0, out, 0, first.length);
        System.arraycopy(second, 0, out, first.length, second.length);
        return out;
    }

    @Test
    void theCheckReadsTheRosterExactlyOnce() {
        rosterIsAvailable(rosterWith(PlacementTestFixtures.FEDERATION_ID, PlacementTestFixtures.DOMAIN,
                PlacementTestFixtures.publicKeyBase64(pair), "ACTIVE"));

        check(publishing()).verifyPlacementSigningIdentity();

        assertThat(org.mockito.Mockito.mockingDetails(resolver).getInvocations().stream()
                .filter(invocation -> invocation.getMethod().getName().equals("fetchRoster"))
                .count()).isEqualTo(1);
    }
}
