package com.example.vuln;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.X509TrustManager;

public class CryptoService {

    public byte[] hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes());
    }

    public byte[] weakSha(String data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data.getBytes());
    }

    public Cipher weakCipher() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }

    public Cipher ecbAes() throws Exception {
        return Cipher.getInstance("AES");
    }

    public SecretKeySpec hardcodedKey() {
        return new SecretKeySpec("1234567890123456".getBytes(), "AES");
    }

    public IvParameterSpec staticIv() {
        return new IvParameterSpec("0000000000000000".getBytes());
    }

    public void weakKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
    }

    public X509TrustManager trustAll() {
        return new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }

            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }
        };
    }

    public void disableHostnameVerification() {
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    }
}
