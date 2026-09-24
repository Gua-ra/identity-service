// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.service.authority;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.account.authority.AuthorityHeadRecord;
import me.sarahlacerda.gua.identityservice.account.authority.AuthorityHeadRecordCodec;
import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.account.genesis.Ed25519Keys;
import me.sarahlacerda.gua.identityservice.account.genesis.TestEd25519;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties;
import me.sarahlacerda.gua.identityservice.config.IdentityServiceProperties.HomeserverConfig;
import me.sarahlacerda.gua.identityservice.service.placement.FederationIds;
import me.sarahlacerda.gua.identityservice.service.placement.RosterMembershipKeys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The signer: it produces bytes that verify under the homeserver's own roster membership key, which is the
 * same key a generation-1 placement record is signed with and the same key the resolver looks up in that
 * homeserver's ACTIVE roster entry.
 */
class AuthorityHeadSignerTest {

    private static final String FEDERATION_ID = "hs-alpha";
    private static final String HEAD_HASH =
            "98e09606da1f3021004badbccfb1f25eff5afb436787850651b92d118ce68510";

    private final TestEd25519.Pair pair = TestEd25519.generate();
    private final Instant now = Instant.parse("2026-09-24T12:00:00Z");
    private final byte[] reference =
            AccountId.derive(AccountId.CLASS_BOOTSTRAP, "one".getBytes()).rawBytes();

    private IdentityServiceProperties publishing() {
        IdentityServiceProperties properties = new IdentityServiceProperties();
        HomeserverConfig homeserver = new HomeserverConfig();
        homeserver.setId("primary");
        homeserver.setDomain("example.test");
        homeserver.setAdminApiBaseUrl("http://admin.invalid");
        homeserver.setClientApiBaseUrl("http://client.invalid");
        homeserver.setAdminAccessToken("not-a-real-token");
        homeserver.setFederationId(FEDERATION_ID);
        homeserver.setPlacementSigningPrivateKey(
                Base64.getEncoder().encodeToString(pair.privateKey().getEncoded()));
        properties.getRouting().getHomeservers().add(homeserver);
        properties.getAuthority().getPublication().setEnabled(true);
        properties.getAuthority().getPublication().setHomeserverId(FEDERATION_ID);
        properties.getAuthority().getPublication().setResolverBaseUrl("http://resolver.invalid");
        return properties;
    }

    private AuthorityHeadSigner signer(IdentityServiceProperties properties) {
        return new AuthorityHeadSigner(properties,
                new RosterMembershipKeys(properties, new FederationIds(properties)));
    }

    @Test
    void aSignedHeadVerifiesUnderTheHomeserversRosterKey() {
        AuthorityHeadSigner.SignedHead signed = signer(publishing()).sign(reference, HEAD_HASH, 3L, now);

        byte[] canonical = Base64.getUrlDecoder().decode(signed.recordB64());
        byte[] signature = Base64.getDecoder().decode(signed.signatureB64());
        assertThat(Ed25519Keys.verify(pair.rawPublicKey(),
                AuthorityHeadRecordCodec.signaturePreimage(canonical), signature)).isTrue();

        AuthorityHeadRecord decoded = AuthorityHeadRecordCodec.decode(canonical);
        assertThat(decoded.accountReference()).isEqualTo(reference);
        assertThat(decoded.headHashHex()).isEqualTo(HEAD_HASH);
        assertThat(decoded.headSeq()).isEqualTo(3L);
        assertThat(decoded.homeserverId()).isEqualTo(FEDERATION_ID);
        assertThat(decoded.issuedAt()).isEqualTo(now);
        assertThat(decoded.notAfter()).isEqualTo(now.plus(Duration.ofDays(400)));
    }

    @Test
    void thePayloadHashItReportsIsTheOneTheLeafWouldCommit() {
        AuthorityHeadSigner.SignedHead signed = signer(publishing()).sign(reference, HEAD_HASH, 1L, now);

        byte[] canonical = Base64.getUrlDecoder().decode(signed.recordB64());

        assertThat(signed.payloadHash())
                .isEqualTo(AuthorityHeadRecordCodec.decode(canonical).payloadHashHex());
    }

    @Test
    void theHeadHashIsCarriedWhicheverCaseItArrivesIn() {
        AuthorityHeadSigner.SignedHead signed =
                signer(publishing()).sign(reference, HEAD_HASH.toUpperCase(java.util.Locale.ROOT), 1L, now);

        // The head row holds lowercase hex, but the state response and the clients compare case-insensitively,
        // so an uppercase value must produce the same bytes rather than a different spelling of them.
        byte[] canonical = Base64.getUrlDecoder().decode(signed.recordB64());
        assertThat(AuthorityHeadRecordCodec.decode(canonical).headHash())
                .isEqualTo(HexFormat.of().parseHex(HEAD_HASH));
        assertThat(signed.headHash()).isEqualTo(HEAD_HASH);
    }

    @Test
    void anotherMembersKeyDoesNotVerifyIt() {
        TestEd25519.Pair other = TestEd25519.generate();
        AuthorityHeadSigner.SignedHead signed = signer(publishing()).sign(reference, HEAD_HASH, 1L, now);

        assertThat(Ed25519Keys.verify(other.rawPublicKey(),
                AuthorityHeadRecordCodec.signaturePreimage(Base64.getUrlDecoder().decode(signed.recordB64())),
                Base64.getDecoder().decode(signed.signatureB64()))).isFalse();
    }

    @Test
    void theSameSignatureDoesNotVerifyOverAnotherAccountsHead() {
        AuthorityHeadSigner signer = signer(publishing());
        AuthorityHeadSigner.SignedHead signed = signer.sign(reference, HEAD_HASH, 1L, now);
        byte[] otherReference = AccountId.derive(AccountId.CLASS_BOOTSTRAP, "two".getBytes()).rawBytes();
        byte[] otherCanonical = Base64.getUrlDecoder()
                .decode(signer.sign(otherReference, HEAD_HASH, 1L, now).recordB64());

        assertThat(Ed25519Keys.verify(pair.rawPublicKey(),
                AuthorityHeadRecordCodec.signaturePreimage(otherCanonical),
                Base64.getDecoder().decode(signed.signatureB64()))).isFalse();
    }

    @Test
    void withNoHomeserverConfiguredNothingCanBeSigned() {
        IdentityServiceProperties properties = new IdentityServiceProperties();

        AuthorityHeadSigner signer = signer(properties);

        assertThat(signer.homeserverId()).isEmpty();
        assertThat(signer.canSign()).isFalse();
        assertThatThrownBy(() -> signer.sign(reference, HEAD_HASH, 1L, now))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void withNoMembershipKeyForTheNamedHomeserverNothingCanBeSigned() {
        IdentityServiceProperties properties = new IdentityServiceProperties();
        properties.getAuthority().getPublication().setHomeserverId("hs-somebody-else");

        AuthorityHeadSigner signer = signer(properties);

        // Naming a homeserver this deployment holds no key for is a deployment error, which the startup check
        // refuses outright. The signer refuses rather than signing under whatever key it does hold.
        assertThat(signer.canSign()).isFalse();
        assertThatThrownBy(() -> signer.sign(reference, HEAD_HASH, 1L, now))
                .isInstanceOf(IllegalStateException.class);
    }
}
