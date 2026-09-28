#Gentry Bayer, Secure Coding Project   
# Secure Coding Project - Password Hasher Implementation
# September 27, 2026 
# Password hasher using PBKDF2-HMAC-SHA256 with per-password random salt

from typing import final
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

** PBKDF2-HMAC-SHA256 with per-password random salt (JDK only, no dependencies). */
public final class PasswordHasher {
    private static final int ITERATIONS = 600_000;   // OWASP guidance for PBKDF2-HMAC-SHA256
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS   = 256;
    private static final SecureRandom RNG = new SecureRandom();

    public static String hashPassword(char[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = new byte[SALT_BYTES];
        RNG.nextBytes(salt);
        byte[] hash = pbkdf2(password, salt, ITERATIONS);
        // Store parameters with the hash so they can be upgraded later
        return ITERATIONS + ":" + Base64.getEncoder().encodeToString(salt)
                          + ":" + Base64.getEncoder().encodeToString(hash);
    }

    public static boolean verifyPassword(char[] password, String stored) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String[] parts = stored.split(":");
        int iterations = Integer.parseInt(parts[0]);
        byte[] salt     = Base64.getDecoder().decode(parts[1]);
        byte[] expected = Base64.getDecoder().decode(parts[2]);
        byte[] actual   = pbkdf2(password, salt, iterations);
        return MessageDigest.isEqual(expected, actual);   // constant-time comparison
    }

    private static byte[] pbkdf2(char[] pw, byte[] salt, int iterations) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(pw, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }
}
