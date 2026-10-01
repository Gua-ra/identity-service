// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.nio.charset.StandardCharsets;

import me.sarahlacerda.gua.identityservice.account.genesis.Ed25519Keys;

/** Signature preimages. A record signature covers {@code magic || challenge || canonicalBytes}. */
public final class AuthorityProofs {

    public static final String APPROVAL_DOMAIN = "gua-authority-approval.v1";

    public static final int APPROVAL_ID_LENGTH = 16;

    public static final String NOTIFICATION_DOMAIN = "gua-authority-notification.v1";

    private static final byte[] APPROVAL_DOMAIN_BYTES = APPROVAL_DOMAIN.getBytes(StandardCharsets.US_ASCII);

    private static final byte[] NOTIFICATION_DOMAIN_BYTES =
            NOTIFICATION_DOMAIN.getBytes(StandardCharsets.US_ASCII);

    public static final int APPROVAL_PREIMAGE_LENGTH = APPROVAL_DOMAIN_BYTES.length
            + AuthorityRecord.ACCOUNT_REFERENCE_LENGTH + APPROVAL_ID_LENGTH + AuthorityRecord.HASH_LENGTH
            + AuthorityRecord.CHALLENGE_LENGTH;

    public static final int NOTIFICATION_PREIMAGE_LENGTH = NOTIFICATION_DOMAIN_BYTES.length
            + AuthorityRecord.ACCOUNT_REFERENCE_LENGTH + AuthorityRecord.HASH_LENGTH
            + AuthorityRecord.KEY_LENGTH + AuthorityRecord.CHALLENGE_LENGTH;

    private AuthorityProofs() {
    }

    public static byte[] recordPreimage(AuthorityRecordType type, byte[] challenge, byte[] canonicalBytes) {
        if (challenge == null || challenge.length != AuthorityRecord.CHALLENGE_LENGTH) {
            throw new IllegalArgumentException("an authority challenge is "
                    + AuthorityRecord.CHALLENGE_LENGTH + " bytes");
        }
        if (canonicalBytes == null || canonicalBytes.length != type.length()) {
            throw new IllegalArgumentException(type + " is " + type.length() + " bytes");
        }
        byte[] magic = type.magicBytes();
        byte[] preimage = new byte[magic.length + challenge.length + canonicalBytes.length];
        int offset = 0;
        System.arraycopy(magic, 0, preimage, offset, magic.length);
        offset += magic.length;
        System.arraycopy(challenge, 0, preimage, offset, challenge.length);
        offset += challenge.length;
        System.arraycopy(canonicalBytes, 0, preimage, offset, canonicalBytes.length);
        return preimage;
    }

    /** Checks the signature only. The caller must still check that the key is authorized for this account. */
    public static boolean verifyRecord(AuthorityRecord record, byte[] challenge, byte[] signature) {
        return Ed25519Keys.verify(record.verifyingKey(),
                recordPreimage(record.type(), challenge, record.canonicalBytes()), signature);
    }

    public static byte[] approvalPreimage(byte[] accountReference, byte[] approvalId, byte[] actionDigest,
            byte[] challenge) {
        require(accountReference, AuthorityRecord.ACCOUNT_REFERENCE_LENGTH, "the account reference");
        require(approvalId, APPROVAL_ID_LENGTH, "an approval id");
        require(actionDigest, AuthorityRecord.HASH_LENGTH, "an action digest");
        require(challenge, AuthorityRecord.CHALLENGE_LENGTH, "an approval challenge");

        byte[] preimage = new byte[APPROVAL_PREIMAGE_LENGTH];
        int offset = 0;
        System.arraycopy(APPROVAL_DOMAIN_BYTES, 0, preimage, offset, APPROVAL_DOMAIN_BYTES.length);
        offset += APPROVAL_DOMAIN_BYTES.length;
        System.arraycopy(accountReference, 0, preimage, offset, accountReference.length);
        offset += accountReference.length;
        System.arraycopy(approvalId, 0, preimage, offset, approvalId.length);
        offset += approvalId.length;
        System.arraycopy(actionDigest, 0, preimage, offset, actionDigest.length);
        offset += actionDigest.length;
        System.arraycopy(challenge, 0, preimage, offset, challenge.length);
        return preimage;
    }

    public static boolean verifyApproval(byte[] deviceKey, byte[] accountReference, byte[] approvalId,
            byte[] actionDigest, byte[] challenge, byte[] signature) {
        return Ed25519Keys.verify(deviceKey,
                approvalPreimage(accountReference, approvalId, actionDigest, challenge), signature);
    }

    public static byte[] notificationPreimage(byte[] accountReference, byte[] installationIdHash, byte[] deviceKey,
            byte[] challenge) {
        require(accountReference, AuthorityRecord.ACCOUNT_REFERENCE_LENGTH, "the account reference");
        require(installationIdHash, AuthorityRecord.HASH_LENGTH, "an installation id hash");
        require(deviceKey, AuthorityRecord.KEY_LENGTH, "a device key");
        require(challenge, AuthorityRecord.CHALLENGE_LENGTH, "a notification challenge");

        byte[] preimage = new byte[NOTIFICATION_PREIMAGE_LENGTH];
        int offset = 0;
        System.arraycopy(NOTIFICATION_DOMAIN_BYTES, 0, preimage, offset, NOTIFICATION_DOMAIN_BYTES.length);
        offset += NOTIFICATION_DOMAIN_BYTES.length;
        System.arraycopy(accountReference, 0, preimage, offset, accountReference.length);
        offset += accountReference.length;
        System.arraycopy(installationIdHash, 0, preimage, offset, installationIdHash.length);
        offset += installationIdHash.length;
        System.arraycopy(deviceKey, 0, preimage, offset, deviceKey.length);
        offset += deviceKey.length;
        System.arraycopy(challenge, 0, preimage, offset, challenge.length);
        return preimage;
    }

    public static boolean verifyNotificationBinding(byte[] deviceKey, byte[] accountReference,
            byte[] installationIdHash, byte[] challenge, byte[] signature) {
        return Ed25519Keys.verify(deviceKey,
                notificationPreimage(accountReference, installationIdHash, deviceKey, challenge), signature);
    }

    private static void require(byte[] value, int length, String what) {
        if (value == null || value.length != length) {
            throw new IllegalArgumentException(what + " is " + length + " bytes");
        }
    }
}
