// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import org.junit.jupiter.api.Test;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;
import me.sarahlacerda.gua.identityservice.account.genesis.TestEd25519;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * The refusal rules of ADM-009 decision 2, each named by the token a client will see.
 *
 * <p>Every rule is tested as a behaviour rather than as the presence of a line, because the decoder is the only
 * thing standing between a malformed record and a chain that commits it forever.
 */
class AuthorityRecordCodecTest {

    private final TestEd25519.Pair device = TestEd25519.generate();
    private final TestEd25519.Pair recovery = TestEd25519.generate();
    private final TestEd25519.Pair authorizing = TestEd25519.generate();

    @Test
    void theAccountReferenceIsExactlyTheBytesAnAccountIdCarries() {
        assertThat(AuthorityRecord.ACCOUNT_REFERENCE_LENGTH).isEqualTo(AccountId.RAW_LENGTH);
    }

    @Test
    void everyTypeHasTheLengthTheRecordTables() {
        assertThat(AuthorityRecordType.ADOPT_ROOT.length()).isEqualTo(177);
        assertThat(AuthorityRecordType.DEVICE_GRANT.length()).isEqualTo(161);
        assertThat(AuthorityRecordType.DEVICE_REVOKE.length()).isEqualTo(145);
        assertThat(AuthorityRecordType.AUTHORITY_RECOVERY.length()).isEqualTo(209);
    }

    @Test
    void anAdoptRootRoundTripsWithItsFieldsAtTheirOffsets() {
        byte[] bytes = AuthorityRecords.adoptRoot(device.rawPublicKey(), recovery.rawPublicKey(), "iPhone", 1,
                AuthorityRecord.emptyPrevHash());

        AuthorityRecord record = AuthorityRecordCodec.decode(bytes);

        assertThat(record.type()).isEqualTo(AuthorityRecordType.ADOPT_ROOT);
        assertThat(record.seq()).isEqualTo(1);
        assertThat(record.deviceKey()).isEqualTo(device.rawPublicKey());
        assertThat(record.recoveryAuthorityKey()).isEqualTo(recovery.rawPublicKey());
        assertThat(record.label()).isEqualTo("iPhone");
        assertThat(record.accountReference()).isEqualTo(AuthorityRecords.REFERENCE);
        assertThat(record.prevHashHex()).isEqualTo(AuthorityRecord.emptyHeadHash());
        // Signed by the key it installs, which is what verifyingKey reports for a type carrying no
        // authorizingKey field.
        assertThat(record.verifyingKey()).isEqualTo(device.rawPublicKey());
    }

    @Test
    void theDecodedRecordKeepsTheBytesItWasGivenRatherThanARecoding() {
        byte[] bytes = AuthorityRecords.grant(device.rawPublicKey(), authorizing.rawPublicKey(), "iPad", 2,
                new byte[32]);

        assertThat(AuthorityRecordCodec.decode(bytes).canonicalBytes()).isEqualTo(bytes);
    }

    @Test
    void aWrongLengthIsRefusedByLengthAndNotByAFieldInside() {
        byte[] bytes = AuthorityRecords.revoke(device.rawPublicKey(), authorizing.rawPublicKey(),
                AuthorityRecord.REASON_LOST, 3, new byte[32]);

        assertThat(reasonFor(AuthorityRecords.truncated(bytes))).isEqualTo("wrong_length");
    }

    @Test
    void anUnknownMagicIsRefusedWhichIsAlsoHowAGenesisObjectIsRefusedHere() {
        byte[] bytes = AuthorityRecords.adoptRoot(device.rawPublicKey(), recovery.rawPublicKey(), "a", 1,
                new byte[32]);

        assertThat(reasonFor(AuthorityRecords.withBytes(bytes, 0, "GUAG".getBytes()))).isEqualTo("bad_magic");
    }

    @Test
    void anUnknownVersionOrSuiteIsRefused() {
        byte[] bytes = AuthorityRecords.adoptRoot(device.rawPublicKey(), recovery.rawPublicKey(), "a", 1,
                new byte[32]);

        assertThat(reasonFor(AuthorityRecords.withByte(bytes, 4, 0x02))).isEqualTo("unknown_version");
        assertThat(reasonFor(AuthorityRecords.withByte(bytes, 5, 0x02))).isEqualTo("unknown_suite");
    }

    @Test
    void aSeqBelowOneIsRefusedBecausePositionsCountFromOne() {
        byte[] bytes = AuthorityRecords.adoptRoot(device.rawPublicKey(), recovery.rawPublicKey(), "a", 1,
                new byte[32]);

        assertThat(reasonFor(AuthorityRecords.withSeq(bytes, 0))).isEqualTo("bad_seq");
        // An unsigned field read as a negative long is the same defect and is refused by the same rule.
        assertThat(reasonFor(AuthorityRecords.withSeq(bytes, -1))).isEqualTo("bad_seq");
    }

    @Test
    void anAllZeroKeyIsRefusedSeparatelyFromPointDecoding() {
        byte[] bytes = AuthorityRecords.adoptRoot(device.rawPublicKey(), recovery.rawPublicKey(), "a", 1,
                new byte[32]);

        // The all-zero encoding decodes to a valid low-order point, so point decoding alone would let it
        // through. That is why the two rules are separate.
        assertThat(reasonFor(AuthorityRecords.withBytes(bytes, 80, new byte[32]))).isEqualTo("zero_device_key");
        assertThat(reasonFor(AuthorityRecords.withBytes(bytes, 113, new byte[32]))).isEqualTo("zero_recovery_key");
    }

    @Test
    void aKeyThatIsNotACurvePointIsRefused() {
        byte[] bytes = AuthorityRecords.adoptRoot(device.rawPublicKey(), recovery.rawPublicKey(), "a", 1,
                new byte[32]);
        byte[] offCurve = new byte[32];
        java.util.Arrays.fill(offCurve, (byte) 0xFF);

        assertThat(reasonFor(AuthorityRecords.withBytes(bytes, 80, offCurve))).isEqualTo("invalid_device_key");
    }

    @Test
    void aRecoveryKeyEqualToTheDeviceKeyInTheSameRecordIsRefused() {
        byte[] bytes = AuthorityRecords.adoptRoot(device.rawPublicKey(), device.rawPublicKey(), "a", 1,
                new byte[32]);

        assertThat(reasonFor(bytes)).isEqualTo("duplicate_keys");
    }

    @Test
    void anUnknownRecoveryFrameworkIsRefused() {
        byte[] bytes = AuthorityRecords.adoptRoot(device.rawPublicKey(), recovery.rawPublicKey(), "a", 1,
                new byte[32]);

        assertThat(reasonFor(AuthorityRecords.withByte(bytes, 112, 0x02)))
                .isEqualTo("unknown_recovery_framework");
    }

    @Test
    void aLabelWithANonZeroByteAfterItsFirstZeroIsRefused() {
        byte[] label = AuthorityRecordCodec.labelBytes("ab");
        label[5] = 'x';
        byte[] bytes = AuthorityRecords.withBytes(
                AuthorityRecords.adoptRoot(device.rawPublicKey(), recovery.rawPublicKey(), "ab", 1, new byte[32]),
                145, label);

        assertThat(reasonFor(bytes)).isEqualTo("non_canonical_label");
    }

    @Test
    void aFullLengthLabelIsAcceptedWithNoPaddingToCheck() {
        byte[] bytes = AuthorityRecords.adoptRoot(device.rawPublicKey(), recovery.rawPublicKey(), "0123456789abcdef",
                1, new byte[32]);

        assertThat(AuthorityRecordCodec.decode(bytes).label()).isEqualTo("0123456789abcdef");
    }

    @Test
    void aReservedGrantFlagIsRefusedRatherThanIgnored() {
        byte[] bytes = AuthorityRecords.grant(device.rawPublicKey(), authorizing.rawPublicKey(), "a", 2,
                new byte[32]);

        assertThat(reasonFor(AuthorityRecords.withByte(bytes, 112, 0x01))).isEqualTo("unknown_flags");
    }

    @Test
    void anUnknownRevocationReasonIsRefused() {
        byte[] bytes = AuthorityRecords.revoke(device.rawPublicKey(), authorizing.rawPublicKey(),
                AuthorityRecord.REASON_LOST, 2, new byte[32]);

        assertThat(reasonFor(AuthorityRecords.withByte(bytes, 112, 0x00))).isEqualTo("unknown_revocation_reason");
        assertThat(reasonFor(AuthorityRecords.withByte(bytes, 112, 0x05))).isEqualTo("unknown_revocation_reason");
    }

    @Test
    void aGrantAndARevocationNameTheKeyThatAuthorizesThem() {
        byte[] grant = AuthorityRecords.grant(device.rawPublicKey(), authorizing.rawPublicKey(), "a", 2,
                new byte[32]);
        byte[] revoke = AuthorityRecords.revoke(device.rawPublicKey(), authorizing.rawPublicKey(),
                AuthorityRecord.REASON_REPLACED, 3, new byte[32]);

        assertThat(AuthorityRecordCodec.decode(grant).verifyingKey()).isEqualTo(authorizing.rawPublicKey());
        assertThat(AuthorityRecordCodec.decode(revoke).verifyingKey()).isEqualTo(authorizing.rawPublicKey());
    }

    @Test
    void aSelfRevocationIsTheOneWhoseNamedDeviceIsItsOwnSigner() {
        byte[] other = AuthorityRecords.revoke(device.rawPublicKey(), authorizing.rawPublicKey(),
                AuthorityRecord.REASON_LOST, 2, new byte[32]);
        byte[] itself = AuthorityRecords.revoke(device.rawPublicKey(), device.rawPublicKey(),
                AuthorityRecord.REASON_LOST, 2, new byte[32]);

        assertThat(AuthorityRecordCodec.decode(other).isSelfRevocation()).isFalse();
        assertThat(AuthorityRecordCodec.decode(itself).isSelfRevocation()).isTrue();
    }

    @Test
    void aZeroAuthorizingKeyOnAGrantIsRefusedBecauseOnlyOneRecordMayCarryOne() {
        byte[] bytes = AuthorityRecords.grant(device.rawPublicKey(), new byte[32], "a", 2, new byte[32]);

        assertThat(reasonFor(bytes)).isEqualTo("zero_authorizing_key");
    }

    @Test
    void theRecoveryAuthorizationPairingIsEnforcedInBothDirections() {
        byte[] byRecoveryKeyWithNoKey = AuthorityRecords.recovery(device.rawPublicKey(), recovery.rawPublicKey(),
                AuthorityRecord.AUTHORIZATION_RECOVERY_KEY, new byte[32], 2, new byte[32]);
        byte[] byAccountRecoveryWithAKey = AuthorityRecords.recovery(device.rawPublicKey(), recovery.rawPublicKey(),
                AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY, authorizing.rawPublicKey(), 2, new byte[32]);

        // One direction alone would leave a record that says it was authorized by a key and names none, or one
        // that says it was not and names one anyway.
        assertThat(reasonFor(byRecoveryKeyWithNoKey)).isEqualTo("authorizing_key_required");
        assertThat(reasonFor(byAccountRecoveryWithAKey)).isEqualTo("authorizing_key_not_permitted");
    }

    @Test
    void theAccountRecoveryAuthorizationIsSignedByTheDeviceItInstalls() {
        byte[] bytes = AuthorityRecords.recovery(device.rawPublicKey(), recovery.rawPublicKey(),
                AuthorityRecord.AUTHORIZATION_ACCOUNT_RECOVERY, new byte[32], 2, new byte[32]);

        AuthorityRecord record = AuthorityRecordCodec.decode(bytes);

        assertThat(record.authorizingKeyField()).isNull();
        assertThat(record.verifyingKey()).isEqualTo(device.rawPublicKey());
    }

    @Test
    void theRecoveryKeyAuthorizationIsSignedByTheKeyItNames() {
        byte[] bytes = AuthorityRecords.recovery(device.rawPublicKey(), recovery.rawPublicKey(),
                AuthorityRecord.AUTHORIZATION_RECOVERY_KEY, authorizing.rawPublicKey(), 2, new byte[32]);

        assertThat(AuthorityRecordCodec.decode(bytes).verifyingKey()).isEqualTo(authorizing.rawPublicKey());
    }

    @Test
    void anUnknownRecoveryAuthorizationIsRefused() {
        byte[] bytes = AuthorityRecords.recovery(device.rawPublicKey(), recovery.rawPublicKey(), 0x03,
                authorizing.rawPublicKey(), 2, new byte[32]);

        assertThat(reasonFor(bytes)).isEqualTo("unknown_authorization");
    }

    @Test
    void theEncoderRefusesAWrongSizedFieldRatherThanTruncatingIt() {
        assertThatThrownBy(() -> AuthorityRecordCodec.encode(AuthorityRecordType.DEVICE_REVOKE,
                new byte[10], new byte[32], 1, new byte[65]))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AuthorityRecordCodec.labelBytes("this label is far too long"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static String reasonFor(byte[] bytes) {
        InvalidAuthorityRecordException refusal = catchThrowableOfType(
                () -> AuthorityRecordCodec.decode(bytes), InvalidAuthorityRecordException.class);
        assertThat(refusal).as("expected these bytes to be refused").isNotNull();
        return refusal.reason();
    }
}
