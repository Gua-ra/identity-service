// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.nio.charset.StandardCharsets;

import me.sarahlacerda.gua.identityservice.account.genesis.Ed25519Keys;

/**
 * The one preimage rule of the authority chain, and the browser-approval preimage beside it (ADM-009
 * decisions 2 and 6).
 *
 * <p><b>One preimage, for every type.</b> A record is verified against
 *
 * <pre>
 * magic || the 32 bytes of the server challenge minted for that transition || the canonical bytes
 * </pre>
 *
 * <p>Three properties follow, and all three are needed:
 * <ul>
 * <li>the magic is the signature domain, so no record can be replayed as another type;</li>
 * <li>the accountId reference is inside the canonical bytes, so none can be replayed into another
 * account;</li>
 * <li>the challenge is inside every signature, so no record is precomputable on other hardware,
 * transferable to another party, or resubmittable after it was opposed.</li>
 * </ul>
 *
 * <p>Revision 2 of ADM-009 fixed this preimage for {@code AdoptRoot} alone, which left the grant, the
 * revocation and the recovery as exactly the unbound blobs the review had objected to. One builder used by
 * every type is the fix, so there is no per-type place for the rule to go missing. It is deliberately the
 * same shape as {@code GenesisProofs}: a domain, then the server's bytes, then the object's bytes, all
 * fixed length except the object, whose length is fixed by its own type.
 *
 * <p>The record's magic stands in for a separate ASCII domain string. {@code GenesisProofs} spells its
 * domains out because a genesis object's magic is shared by both proofs it takes; here each record type has
 * its own magic already, so a second constant would be a second thing to keep in step for nothing.
 */
public final class AuthorityProofs {

    /** The domain a device signs when it approves an action a browser session started (decision 6). */
    public static final String APPROVAL_DOMAIN = "gua-authority-approval.v1";

    /** Bytes of a pending-approval id inside the preimage. */
    public static final int APPROVAL_ID_LENGTH = 16;

    /** The domain an install signs to bind its security-notification registration to a device key. */
    public static final String NOTIFICATION_DOMAIN = "gua-authority-notification.v1";

    private static final byte[] APPROVAL_DOMAIN_BYTES = APPROVAL_DOMAIN.getBytes(StandardCharsets.US_ASCII);

    private static final byte[] NOTIFICATION_DOMAIN_BYTES =
            NOTIFICATION_DOMAIN.getBytes(StandardCharsets.US_ASCII);

    /** 25 + 34 + 16 + 32 + 32. */
    public static final int APPROVAL_PREIMAGE_LENGTH = APPROVAL_DOMAIN_BYTES.length
            + AuthorityRecord.ACCOUNT_REFERENCE_LENGTH + APPROVAL_ID_LENGTH + AuthorityRecord.HASH_LENGTH
            + AuthorityRecord.CHALLENGE_LENGTH;

    /** 29 + 34 + 32 + 32 + 32. */
    public static final int NOTIFICATION_PREIMAGE_LENGTH = NOTIFICATION_DOMAIN_BYTES.length
            + AuthorityRecord.ACCOUNT_REFERENCE_LENGTH + AuthorityRecord.HASH_LENGTH
            + AuthorityRecord.KEY_LENGTH + AuthorityRecord.CHALLENGE_LENGTH;

    private AuthorityProofs() {
    }

    /**
     * The preimage every authority record is verified against.
     *
     * @param challenge      the 32 server-minted bytes held against this account and this stepped-up
     *                       session, never a value read from the request
     * @param canonicalBytes the record's bytes as received, never a re-encoding
     */
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

    /**
     * Verifies a record under the key its own type names.
     *
     * <p>The key comes from {@link AuthorityRecord#verifyingKey()}, and the caller still has to decide
     * whether that key is one this account's chain accepts at this position. Holding a valid signature by
     * a key nobody granted is not authority.
     */
    public static boolean verifyRecord(AuthorityRecord record, byte[] challenge, byte[] signature) {
        return Ed25519Keys.verify(record.verifyingKey(),
                recordPreimage(record.type(), challenge, record.canonicalBytes()), signature);
    }

    /**
     * The preimage an authority device signs to approve an action reached from a browser (decision 6):
     * the domain, the accountId reference, the pending approval id, the action digest and the challenge.
     *
     * <p>Every element is fixed length, so no field can be shifted into another. The action digest is what
     * makes the approval specific: a malicious page can start an approval the user never wanted, and what
     * defends that is the code plus a device-side description of this exact digest, on a screen the page
     * does not control.
     */
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

    /** Verifies an approval signature under one active device key. */
    public static boolean verifyApproval(byte[] deviceKey, byte[] accountReference, byte[] approvalId,
            byte[] actionDigest, byte[] challenge, byte[] signature) {
        return Ed25519Keys.verify(deviceKey,
                approvalPreimage(accountReference, approvalId, actionDigest, challenge), signature);
    }

    /**
     * The preimage an install signs to bind its security-notification registration to a device authority key
     * (ADM-009 gate 2, the removal tiers).
     *
     * <p>Why it has to be signed rather than asserted. A registration that carries a device key needs a
     * signature by that key before it may be removed from another install, so the key on the row is the
     * thing standing between an attacker with a fresh post-recovery session and an empty channel. If the
     * field could simply be claimed, an attacker would name the owner's key on their own row, and, worse, a
     * row could be planted that the owner's own device can never remove.
     *
     * <p>The installation id is hashed rather than carried, so every element is fixed length and no field can
     * be shifted into another, exactly as in {@link #approvalPreimage}. ADM-009 does not define this
     * preimage; it is the wire addition gate 2's own removal tiers need, and it is stated here so both
     * clients sign the same bytes.
     */
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

    /** Verifies that the install really holds the device key its registration names. */
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
