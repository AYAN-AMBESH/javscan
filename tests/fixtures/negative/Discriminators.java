package run.halo.core.extension;

/**
 * Negative fixture (RC3): five constants whose *names* match the secret
 * pattern but whose *values* are public labels — a Secret type discriminator,
 * a validation regex, a token namespace prefix, an event id and an RFC-7807
 * problem-detail URI. JS401 must not fire on any of them.
 */
public class Discriminators {

    public static final String SECRET_TYPE_OPAQUE = "Opaque";

    public static final String PASSWORD_REGEX = "^[A-Za-z0-9!@#$%^&*.?]+$";

    public static final String PAT_TOKEN_PREFIX = "pat_";

    public static final String RESET_PASSWORD_BY_EMAIL_REASON_TYPE = "reset-password-by-email";

    public static final String INVALID_CREDENTIAL_TYPE = "https://halo.run/probs/invalid-credential";
}
