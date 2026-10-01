// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.account.genesis.TestEd25519;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthorityProofsTest {

    private final TestEd25519.Pair device = TestEd25519.generate();
    private final TestEd25519.Pair recovery = TestEd25519.generate();
    private final SecureRandom random = new SecureRandom();

    @Test
    void thePreimageIsTheMagicThenTheChallengeThenTheCanonicalBytes() {
        byte[] challenge = challenge();
        byte[] bytes = AuthorityRecords.adoptRoot(device.rawPublicKey(), recovery.rawPublicKey(), "a", 1,
                new byte[32]);

        byte[] preimage = AuthorityProofs.recordPreimage(AuthorityRecordType.ADOPT_ROOT, challenge, bytes);

        assertThat(preimage).hasSize(4 + 32 + bytes.length);
        assertThat(Arrays.copyOfRange(preimage, 0, 4)).isEqualTo("GUAA".getBytes());
        assertThat(Arrays.copyOfRange(preimage, 4, 36)).isEqualTo(challenge);
        assertThat(Arrays.copyOfRange(preimage, 36, preimage.length)).isEqualTo(bytes);
    }

    @Test
    void everyTypeIsVerifiedAgainstTheSameRuleAndNotAPerTypeOne() {
        byte[] challenge = challenge();
        for (byte[] bytes : new byte[][] {
                AuthorityRecords.adoptRoot(device.rawPublicKey(), recovery.rawPublicKey(), "a", 1, new byte[32]),
                AuthorityRecords.recovery(device.rawPublicKey(), recovery.rawPublicKey(),
                        AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY, new byte[32], 2, new byte[32]) }) {
            AuthorityRecord record = AuthorityRecordCodec.decode(bytes);
            byte[] signature = TestEd25519.sign(device.privateKey(),
                    AuthorityProofs.recordPreimage(record.type(), challenge, bytes));

            assertThat(AuthorityProofs.verifyRecord(record, challenge, signature)).isTrue();
        }
    }

    @Test
    void aSignatureOverAnotherChallengeDoesNotVerify() {
        byte[] bytes = AuthorityRecords.adoptRoot(device.rawPublicKey(), recovery.rawPublicKey(), "a", 1,
                new byte[32]);
        AuthorityRecord record = AuthorityRecordCodec.decode(bytes);
        byte[] signature = TestEd25519.sign(device.privateKey(),
                AuthorityProofs.recordPreimage(record.type(), challenge(), bytes));

        assertThat(AuthorityProofs.verifyRecord(record, challenge(), signature)).isFalse();
    }

    @Test
    void aRecordCannotBeReplayedAsAnotherTypeBecauseTheMagicIsTheDomain() {
        byte[] challenge = challenge();
        byte[] grantBytes = AuthorityRecords.grant(device.rawPublicKey(), device.rawPublicKey(), "a", 2,
                new byte[32]);
        AuthorityRecord grant = AuthorityRecordCodec.decode(grantBytes);

        byte[] underTheWrongDomain = TestEd25519.sign(device.privateKey(),
                AuthorityProofs.recordPreimage(AuthorityRecordType.DEVICE_REVOKE, challenge, revokeOfSameLengthAs()));

        assertThat(AuthorityProofs.verifyRecord(grant, challenge, underTheWrongDomain)).isFalse();
    }

    @Test
    void aSignatureByAnotherKeyDoesNotVerifyUnderTheKeyTheTypeNames() {
        byte[] challenge = challenge();
        byte[] bytes = AuthorityRecords.grant(device.rawPublicKey(), device.rawPublicKey(), "a", 2, new byte[32]);
        AuthorityRecord record = AuthorityRecordCodec.decode(bytes);
        byte[] byTheWrongKey = TestEd25519.sign(recovery.privateKey(),
                AuthorityProofs.recordPreimage(record.type(), challenge, bytes));

        assertThat(AuthorityProofs.verifyRecord(record, challenge, byTheWrongKey)).isFalse();
    }

    @Test
    void aChallengeOfTheWrongLengthIsRefusedRatherThanPadded() {
        byte[] bytes = AuthorityRecords.adoptRoot(device.rawPublicKey(), recovery.rawPublicKey(), "a", 1,
                new byte[32]);

        assertThatThrownBy(() -> AuthorityProofs.recordPreimage(AuthorityRecordType.ADOPT_ROOT, new byte[31], bytes))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void theApprovalPreimageIsFixedLengthThroughout() {
        byte[] preimage = AuthorityProofs.approvalPreimage(AuthorityRecords.REFERENCE,
                new byte[AuthorityProofs.APPROVAL_ID_LENGTH], new byte[32], challenge());

        assertThat(preimage).hasSize(AuthorityProofs.APPROVAL_PREIMAGE_LENGTH);
        assertThat(Arrays.copyOfRange(preimage, 0, AuthorityProofs.APPROVAL_DOMAIN.length()))
                .isEqualTo(AuthorityProofs.APPROVAL_DOMAIN.getBytes());
    }

    @Test
    void anApprovalSignatureIsBoundToItsActionDigest() {
        byte[] approvalId = new byte[AuthorityProofs.APPROVAL_ID_LENGTH];
        byte[] challenge = challenge();
        byte[] digest = new byte[32];
        random.nextBytes(digest);
        byte[] signature = TestEd25519.sign(device.privateKey(),
                AuthorityProofs.approvalPreimage(AuthorityRecords.REFERENCE, approvalId, digest, challenge));

        assertThat(AuthorityProofs.verifyApproval(device.rawPublicKey(), AuthorityRecords.REFERENCE, approvalId,
                digest, challenge, signature)).isTrue();

        byte[] anotherAction = new byte[32];
        random.nextBytes(anotherAction);
        assertThat(AuthorityProofs.verifyApproval(device.rawPublicKey(), AuthorityRecords.REFERENCE, approvalId,
                anotherAction, challenge, signature)).isFalse();
    }

    private byte[] challenge() {
        byte[] challenge = new byte[AuthorityRecord.CHALLENGE_LENGTH];
        random.nextBytes(challenge);
        return challenge;
    }

    private byte[] revokeOfSameLengthAs() {
        return AuthorityRecords.revoke(device.rawPublicKey(), device.rawPublicKey(), AuthorityRecord.REASON_LOST,
                2, new byte[32]);
    }
}
