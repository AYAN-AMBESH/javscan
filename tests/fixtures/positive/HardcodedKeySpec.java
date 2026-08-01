package fixtures;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** JS304 must still catch key material that really is baked into the source. */
public class HardcodedKeySpec {

    private static final String KEY = "8f2b91c4de07a563";

    public SecretKeySpec inlineLiteral() {
        return new SecretKeySpec("hunter2-hunter2-".getBytes(), "AES");
    }

    public SecretKeySpec viaConstant() {
        return new SecretKeySpec(KEY.getBytes(), "AES");
    }

    public IvParameterSpec fixedIv() {
        return new IvParameterSpec(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
    }
}
