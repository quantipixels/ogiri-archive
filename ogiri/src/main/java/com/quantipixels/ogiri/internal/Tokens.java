// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Quanti Pixels
package com.quantipixels.ogiri.internal;

import com.quantipixels.ogiri.Subject;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public final class Tokens {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    private Tokens() {}

    public static String generate() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return ENCODER.encodeToString(bytes);
    }

    public static byte[] digest(String token) {
        if (token == null || token.length() != 43) return null;
        String encoded = token;
        final byte[] bytes;
        try {
            bytes = Base64.getUrlDecoder().decode(encoded);
        } catch (IllegalArgumentException malformed) {
            return null;
        }
        if (bytes.length != 32 || !ENCODER.encodeToString(bytes).equals(encoded)) return null;
        return sha256().digest(token.getBytes(StandardCharsets.US_ASCII));
    }

    public static String client() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return ENCODER.encodeToString(bytes);
    }

    public static String hexDigest(String token) {
        return java.util.HexFormat.of()
                .formatHex(sha256().digest(token.getBytes(StandardCharsets.US_ASCII)));
    }

    static byte[] lockKey(Subject subject) {
        MessageDigest hash = sha256();
        hash.update("ogiri-session-admission-v1".getBytes(StandardCharsets.US_ASCII));
        for (String part :
                new String[] {subject.realm(), subject.tenantId(), subject.subjectId()}) {
            byte[] bytes = part.getBytes(StandardCharsets.UTF_8);
            hash.update(ByteBuffer.allocate(4).putInt(bytes.length).array());
            hash.update(bytes);
        }
        return hash.digest();
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError(impossible);
        }
    }
}
