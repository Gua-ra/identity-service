// Copyright 2026 Gua
package me.sarahlacerda.gua.identityservice.account.authority;

import java.nio.ByteBuffer;
import java.util.Arrays;

import me.sarahlacerda.gua.identityservice.account.genesis.AccountId;

/** Builds canonical authority records for tests, so each test names only the field it is about. */
public final class AuthorityRecords {

    public static final byte[] REFERENCE =
            AccountId.derive(AccountId.CLASS_BOOTSTRAP, "entropy".getBytes()).rawBytes();

    private AuthorityRecords() {
    }

    public static byte[] adoptRootFor(byte[] reference, byte[] deviceKey, byte[] recoveryKey, String label,
            long seq, byte[] prevHash) {
        return AuthorityRecordCodec.encode(AuthorityRecordType.ADOPT_ROOT, reference, prevHash, seq,
                concat(deviceKey, new byte[] { AuthorityRecord.RECOVERY_FRAMEWORK_COMMITTED_KEY }, recoveryKey,
                        AuthorityRecordCodec.labelBytes(label), new byte[AuthorityRecord.ENTROPY_LENGTH]));
    }

    public static byte[] grantFor(byte[] reference, byte[] deviceKey, byte[] authorizingKey, String label, long seq,
            byte[] prevHash) {
        return AuthorityRecordCodec.encode(AuthorityRecordType.DEVICE_GRANT, reference, prevHash, seq,
                concat(deviceKey, new byte[] { AuthorityRecord.FLAGS_NONE },
                        AuthorityRecordCodec.labelBytes(label), authorizingKey));
    }

    public static byte[] revokeFor(byte[] reference, byte[] deviceKey, byte[] authorizingKey, int reason, long seq,
            byte[] prevHash) {
        return AuthorityRecordCodec.encode(AuthorityRecordType.DEVICE_REVOKE, reference, prevHash, seq,
                concat(deviceKey, new byte[] { (byte) reason }, authorizingKey));
    }

    public static byte[] opposeFor(byte[] reference, byte[] opposedRecordHash, byte[] authorizingKey, long seq,
            byte[] prevHash) {
        return AuthorityRecordCodec.encode(AuthorityRecordType.OPPOSE, reference, prevHash, seq,
                concat(opposedRecordHash, authorizingKey));
    }

    static byte[] oppose(byte[] opposedRecordHash, byte[] authorizingKey, long seq, byte[] prevHash) {
        return opposeFor(REFERENCE, opposedRecordHash, authorizingKey, seq, prevHash);
    }

    static byte[] adoptRoot(byte[] deviceKey, byte[] recoveryKey, String label, long seq, byte[] prevHash) {
        return AuthorityRecordCodec.encode(AuthorityRecordType.ADOPT_ROOT, REFERENCE, prevHash, seq,
                concat(deviceKey, new byte[] { AuthorityRecord.RECOVERY_FRAMEWORK_COMMITTED_KEY }, recoveryKey,
                        AuthorityRecordCodec.labelBytes(label), new byte[AuthorityRecord.ENTROPY_LENGTH]));
    }

    static byte[] grant(byte[] deviceKey, byte[] authorizingKey, String label, long seq, byte[] prevHash) {
        return AuthorityRecordCodec.encode(AuthorityRecordType.DEVICE_GRANT, REFERENCE, prevHash, seq,
                concat(deviceKey, new byte[] { AuthorityRecord.FLAGS_NONE },
                        AuthorityRecordCodec.labelBytes(label), authorizingKey));
    }

    static byte[] revoke(byte[] deviceKey, byte[] authorizingKey, int reason, long seq, byte[] prevHash) {
        return AuthorityRecordCodec.encode(AuthorityRecordType.DEVICE_REVOKE, REFERENCE, prevHash, seq,
                concat(deviceKey, new byte[] { (byte) reason }, authorizingKey));
    }

    static byte[] recovery(byte[] deviceKey, byte[] recoveryKey, int authorization, byte[] authorizingKey,
            long seq, byte[] prevHash) {
        return AuthorityRecordCodec.encode(AuthorityRecordType.AUTHORITY_RECOVERY, REFERENCE, prevHash, seq,
                concat(deviceKey, recoveryKey, AuthorityRecordCodec.labelBytes("phone"),
                        new byte[AuthorityRecord.ENTROPY_LENGTH], new byte[] { (byte) authorization },
                        authorizingKey));
    }

    static byte[] withByte(byte[] record, int offset, int value) {
        byte[] copy = record.clone();
        copy[offset] = (byte) value;
        return copy;
    }

    static byte[] withBytes(byte[] record, int offset, byte[] value) {
        byte[] copy = record.clone();
        System.arraycopy(value, 0, copy, offset, value.length);
        return copy;
    }

    static byte[] withSeq(byte[] record, long seq) {
        byte[] copy = record.clone();
        ByteBuffer.wrap(copy, 72, 8).putLong(seq);
        return copy;
    }

    static byte[] zeros(int length) {
        return new byte[length];
    }

    public static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] out = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    static byte[] truncated(byte[] record) {
        return Arrays.copyOf(record, record.length - 1);
    }
}
