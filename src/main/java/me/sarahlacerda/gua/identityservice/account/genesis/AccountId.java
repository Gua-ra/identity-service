package me.sarahlacerda.gua.identityservice.account.genesis;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * An accountId: {@code "ga1" || base32(0x01 || class || SHA-256(canonical bytes))} (ADM-008 decision 2).
 *
 * <p>The digest covers the canonical bytes <em>as received</em>. Nothing here re-encodes a decoded object
 * before hashing it, because the accountId is permanent: if the bytes that were hashed were not the bytes
 * that crossed the wire, a decoder bug would silently mint a different account.
 *
 * <p>An accountId also has exactly one spelling. The 34 input bytes are 272 bits while the 55 base32
 * characters carry 275, so the last character holds three unused bits and only {@code a}, {@code i},
 * {@code q} and {@code y} can end a well-formed id. A decoder that ignored that would accept eight
 * spellings of one account, which ADM-001 L4 forbids. {@link #parse(String)} therefore applies the
 * tightened pattern, decodes, re-encodes and compares.
 */
public final class AccountId {

    public static final String PREFIX = "ga1";

    /** accountId format version, the first byte under the base32. */
    public static final byte FORMAT_VERSION = 0x01;

    /** Root class byte: the account is rooted in an {@code AccountGenesis}. */
    public static final byte CLASS_GENESIS = 0x01;

    /** Root class byte: the account is a bootstrap account (ADM-001 L5 path B1). */
    public static final byte CLASS_BOOTSTRAP = 0x00;

    /** Bytes under the base32: format version, root class, then the 32-byte digest. */
    public static final int RAW_LENGTH = 34;

    /** Characters of base32 that {@link #RAW_LENGTH} bytes produce. */
    public static final int ENCODED_LENGTH = 55;

    /** Total characters, the {@code ga1} prefix included. */
    public static final int LENGTH = PREFIX.length() + ENCODED_LENGTH;

    /**
     * The canonical spelling, tightened at the last character. Public so the guard tests can assert that
     * no OIDC claim ever matches it (ADM-008 decision 10).
     */
    public static final String CANONICAL_PATTERN = "^ga1[a-z2-7]{54}[aiqy]$";

    private static final Pattern CANONICAL = Pattern.compile(CANONICAL_PATTERN);

    private final String value;
    private final byte[] raw;

    private AccountId(String value, byte[] raw) {
        this.value = value;
        this.raw = raw;
    }

    /**
     * Derives the accountId of an object from the exact bytes received for it.
     *
     * @param rootClass      {@link #CLASS_GENESIS} or {@link #CLASS_BOOTSTRAP}
     * @param canonicalBytes the canonical bytes as received, never a re-encoding of a parsed object
     */
    public static AccountId derive(byte rootClass, byte[] canonicalBytes) {
        requireKnownClass(rootClass);
        byte[] raw = new byte[RAW_LENGTH];
        raw[0] = FORMAT_VERSION;
        raw[1] = rootClass;
        System.arraycopy(sha256(canonicalBytes), 0, raw, 2, 32);
        return new AccountId(PREFIX + Base32.encode(raw), raw);
    }

    /**
     * Parses an accountId, enforcing the canonical form.
     *
     * @throws InvalidGenesisException when the value is not the one canonical spelling of a known
     *                                 format version and root class
     */
    public static AccountId parse(String value) {
        if (value == null || !CANONICAL.matcher(value).matches()) {
            throw new InvalidGenesisException("bad_account_id", "accountId does not match the canonical pattern");
        }
        String encoded = value.substring(PREFIX.length());
        byte[] raw = Base32.decode(encoded);
        if (raw.length != RAW_LENGTH) {
            throw new InvalidGenesisException("bad_account_id", "accountId does not carry " + RAW_LENGTH + " bytes");
        }
        // The pattern already excludes the seven non-canonical last characters; re-encoding and comparing
        // is the rule ADM-008 decision 2 states, and it also catches any future change to either routine.
        if (!Base32.encode(raw).equals(encoded)) {
            throw new InvalidGenesisException("non_canonical_account_id", "accountId is not in canonical form");
        }
        if (raw[0] != FORMAT_VERSION) {
            throw new InvalidGenesisException("unknown_account_id_version", "unknown accountId format version");
        }
        requireKnownClass(raw[1]);
        return new AccountId(value, raw);
    }

    private static void requireKnownClass(byte rootClass) {
        if (rootClass != CLASS_GENESIS && rootClass != CLASS_BOOTSTRAP) {
            throw new InvalidGenesisException("unknown_root_class", "unknown accountId root class");
        }
    }

    /** The 58-character string form. */
    public String value() {
        return value;
    }

    /** The 34 bytes under the base32, which a placement record carries verbatim. */
    public byte[] rawBytes() {
        return raw.clone();
    }

    /** {@link #CLASS_GENESIS} or {@link #CLASS_BOOTSTRAP}. */
    public byte rootClass() {
        return raw[1];
    }

    /** True for a genesis-rooted account, false for a bootstrap one (ADM-001 L5's audit marker). */
    public boolean isGenesisRooted() {
        return rootClass() == CLASS_GENESIS;
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable in this JVM", ex);
        }
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof AccountId id && value.equals(id.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public String toString() {
        return value;
    }

    /** Lowercase hex of the digest half, for logs that want a short handle without the prefix. */
    public String digestHex() {
        return java.util.HexFormat.of().formatHex(Arrays.copyOfRange(raw, 2, RAW_LENGTH));
    }

    /** The ASCII bytes of the string form. */
    public byte[] asciiBytes() {
        return value.getBytes(StandardCharsets.US_ASCII);
    }
}
