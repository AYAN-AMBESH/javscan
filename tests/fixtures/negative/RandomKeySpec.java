package fixtures;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;

/**
 * JS304 must not treat the *algorithm name* argument as key material.
 * Every one of these constructors takes a non-secret string ("AES",
 * "HmacSHA256"), so scanning all arguments for a nested literal fired on
 * every construction, including keys derived from a CSPRNG or from config.
 */
public class RandomKeySpec {

    private String configuredSecret;

    public SecretKey randomKey() {
        return new SecretKeySpec(SecureRandomBytes.of(32), "AES");
    }

    public void hmacFromConfig() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(configuredSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    }

    public GCMParameterSpec randomNonce() {
        byte[] iv = SecureRandomBytes.of(12);
        return new GCMParameterSpec(128, iv);
    }

    // `new byte[32]` is an empty buffer filled in later, not a baked-in key.
    public SecretKey bufferKey() {
        byte[] material = new byte[32];
        SecureRandomBytes.fill(material);
        return new SecretKeySpec(material, "AES");
    }

    static class SecureRandomBytes {
        static byte[] of(int n) {
            return new byte[n];
        }

        static void fill(byte[] b) {
        }
    }
}
