package run.halo.fixture;

/**
 * Positive fixture (RC3): values that really are key material. The name gate
 * must let these through and the value gate must classify them as secrets.
 */
public class RealSecrets {

    // 32 chars, high entropy, key charset
    private static final String API_KEY = "s7Kd93MzQpXv2LbNr8YtWc4HgJf6DaEu";

    private static final String JWT_SECRET = "my-jwt-signing-secret-key-2024";

    private String clientSecret = "Zx91QwErTy73PoIuAsDf45GhJkLm82Nb";
}
