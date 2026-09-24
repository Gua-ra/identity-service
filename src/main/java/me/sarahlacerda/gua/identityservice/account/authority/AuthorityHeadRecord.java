// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.time.Instant;
import java.util.HexFormat;

/**
 * One settled authority-chain head, published so that a verifier can check a head it was handed
 * (ADM-009 decision 12).
 *
 * <p>Decision 12 reserves an {@code ACCOUNT_AUTHORITY} log leaf for the chain head and says, in as many
 * words, that until it is written a class {@code 0x00} account's chain is an assertion by the homeserver
 * that stores it. This is the object that leaf commits: an account reference, the hash of the record at
 * the head of its chain, the position of that record, the roster homeserver asserting it, and a validity
 * window. Nothing else.
 *
 * <p><b>What the leaf commits, and what it does not.</b> The leaf's payload is the SHA-256 of these
 * canonical bytes and nothing more, so the log holds one hash per publication and no field of this object
 * appears in it. The bytes themselves are served beside the leaf, which is what lets a verifier recompute
 * the payload hash from the envelope it was handed and reach the leaf from there.
 *
 * <p><b>What it deliberately does not carry.</b> No phone number, no phone hash, no Matrix user id, no
 * device key, no label, no reason code, and no field that names the human. The account reference is the 34
 * bytes the chain envelope already carries, which is a version byte, a class byte and a 256-bit hash with
 * no identifier in its preimage; {@code headHash} is a hash; {@code headSeq} is a counter; the homeserver
 * id is a roster id. That is ADM-001 L15 and L4, the same reason a placement record is publishable where
 * the deleted {@code phone -> homeserver} directory write was not. Every offset is accounted for in
 * {@link AuthorityHeadRecordCodec}, so there is no room for a field that identifies anybody, and
 * {@code AuthorityHeadRecordCodecTest} fails if this record grows one.
 *
 * <p><b>Only a settled head belongs here.</b> The head row's {@code headHash} also names a record still
 * inside its opposition window, and a cancellation rolls it back to that record's own {@code prevHash}.
 * The log is append-only, so a head published from inside a window would be a leaf about a record that
 * later stops existing. {@code AuthorityHeadPublisher} is where that rule lives; this object cannot tell
 * the difference and does not try to.
 *
 * <p>The object says nothing about what the chain <em>means</em>. It commits which record is at the head,
 * and a verifier reaches the account's device set by replaying the self-evidencing records up to it. That
 * is the division decision 2 set up: each record carries its own {@code authorizingKey} inside the bytes
 * that are hashed, so the head hash is enough to pin the whole history.
 *
 * @param version          format version, {@value #VERSION}
 * @param suite            signature suite, {@value AuthorityRecord#SUITE_ED25519_SHA256}
 * @param accountReference the 34 bytes the chain envelope carries at offset 6
 * @param headHash         SHA-256 over the canonical bytes of the record at the head of the chain
 * @param headSeq          that record's position, 1 or more; a chain with no settled record is not
 *                         publishable, because there is no non-membership proof and an object asserting
 *                         "this account holds nothing" would be one
 * @param homeserverId     the roster entry id of the homeserver that stores the chain and signs this
 *                         object, never the Matrix domain
 * @param issuedAt         when the signer issued it
 * @param notBefore        start of the validity window
 * @param notAfter         end of the validity window, which is what turns a homeserver that stops
 *                         publishing into a visible stale state rather than into silence
 * @param canonicalBytes   the exact bytes the signature covers and the leaf hashes, kept verbatim so
 *                         nothing re-encodes them
 */
public record AuthorityHeadRecord(
        int version,
        int suite,
        byte[] accountReference,
        byte[] headHash,
        long headSeq,
        String homeserverId,
        Instant issuedAt,
        Instant notBefore,
        Instant notAfter,
        byte[] canonicalBytes) {

    /** ASCII magic, and the signature domain separator. Free in the set GUAA, GUAD, GUAX, GUAR, GUAO. */
    public static final String MAGIC = "GUAH";

    /** The versioned domain string this object is named by outside the byte layout. */
    public static final String DOMAIN = "gua-account-authority-head.v1";

    /** The log leaf type decision 12 reserves for it. */
    public static final String LEAF_TYPE = "ACCOUNT_AUTHORITY";

    public static final int VERSION = 0x01;

    /** Bytes before the variable-length homeserver id: magic, version, suite, reference, headHash, seq, n. */
    public static final int FIXED_PREFIX_LENGTH = 81;

    /** Bytes after it: three 8-byte timestamps. */
    public static final int TRAILER_LENGTH = 24;

    /** Total length of an object carrying an {@code n}-byte homeserver id, before {@code n} is added. */
    public static final int LENGTH_WITHOUT_HOMESERVER_ID = FIXED_PREFIX_LENGTH + TRAILER_LENGTH;

    /** As in a placement record: a roster id is an opaque token, not a host name. */
    public static final int MAX_HOMESERVER_ID_LENGTH = 64;

    /** SHA-256 over the canonical bytes, lowercase hex. Exactly what the log leaf's payload hash is. */
    public String payloadHashHex() {
        return HexFormat.of().formatHex(AuthorityRecord.sha256(canonicalBytes));
    }

    /** The head this object attests, in the lowercase hex form the head row and the state response use. */
    public String headHashHex() {
        return HexFormat.of().formatHex(headHash);
    }

    /** A defensive copy: callers must never be able to edit the bytes a signature covers. */
    @Override
    public byte[] canonicalBytes() {
        return canonicalBytes.clone();
    }

    @Override
    public byte[] accountReference() {
        return accountReference.clone();
    }

    @Override
    public byte[] headHash() {
        return headHash.clone();
    }

    /** Never the reference, never the hash: a head is logged by its position and its homeserver only. */
    @Override
    public String toString() {
        return MAGIC + "#" + headSeq + "@" + homeserverId;
    }
}
