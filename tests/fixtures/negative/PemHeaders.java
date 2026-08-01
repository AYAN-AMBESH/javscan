package fixtures;

/**
 * JS401 — every PEM reader declares the header constants it parses against.
 * The header alone is not key material; only a header followed by a base64
 * body is.
 */
public class PemHeaders {

    private static final String PKCS_1_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String PKCS_1_PEM_FOOTER = "-----END RSA PRIVATE KEY-----";
    private static final String PKCS_8_PEM_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PKCS_8_PEM_FOOTER = "-----END PRIVATE KEY-----";

    // A comma-separated list of field names to mask is configuration, not a
    // credential, however well it scores on entropy.
    private String keywords4MaskingSecretsOfConfig =
            "user,password,trustStorePass,keyStorePass,secretKey,authentication";
}
