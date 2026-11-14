
package com.secureworkspace;
import java.security.*;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public final class Security {
    private static final SecureRandom RNG = new SecureRandom();
    // 32 symbols without the look-alikes 0/O and 1/I: every symbol carries exactly 5 bits.
    private static final String CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private Security() {}
    public static String newSalt() {
        byte[] b = new byte[16]; new SecureRandom().nextBytes(b);
        return Base64.getEncoder().encodeToString(b);
    }
    public static String hash(String password, String salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), Base64.getDecoder().decode(salt), 150000, 256);
        try { return Base64.getEncoder().encodeToString(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded()); }
        finally { spec.clearPassword(); }
    }
    public static boolean verify(String password, String salt, String expected) throws Exception {
        return MessageDigest.isEqual(hash(password,salt).getBytes(java.nio.charset.StandardCharsets.UTF_8), expected.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    // ---- account recovery helpers -------------------------------------------------------------

    /** One recovery code: 16 random symbols = 80 bits of entropy, shown as XXXX-XXXX-XXXX-XXXX. */
    public static String newRecoveryCode() {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            if (i > 0 && i % 4 == 0) b.append('-');
            b.append(CODE_ALPHABET.charAt(RNG.nextInt(CODE_ALPHABET.length())));
        }
        return b.toString();
    }
    /** Users may type spaces/dashes/lower-case; the stored hash is always over the normalised form. */
    public static String normalizeCode(String s) {
        return s == null ? "" : s.replaceAll("[\\s-]", "").toUpperCase(Locale.ROOT);
    }
    /** Admin reset ticket: 128 random bits as 8 groups of 4 hex characters. */
    public static String newTicket() {
        byte[] r = new byte[16]; RNG.nextBytes(r);
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < r.length; i++) {
            if (i > 0 && i % 2 == 0) b.append('-');
            b.append(String.format("%02x", r[i]));
        }
        return b.toString();
    }
    public static String normalizeTicket(String s) {
        return s == null ? "" : s.replaceAll("[\\s-]", "").toLowerCase(Locale.ROOT);
    }
    /**
     * Codes and tickets are random with 80+ bits of entropy, so a plain SHA-256 is enough to store them
     * (a slow hash is only needed for human-chosen passwords). The database never holds the secret itself.
     */
    public static String sha256(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder b = new StringBuilder();
            for (byte x : d) b.append(String.format("%02x", x));
            return b.toString();
        } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
}
