package com.huaweicloud.encryptionsdk.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Signature;
import java.util.Locale;
import java.util.Set;

public final class CryptoFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoFactory.class);

    private static final Set<String> SM_ALGORITHMS = Set.of("SM2", "SM3", "SM4", "SM3WITHSM2");

    private CryptoFactory() {
    }

    public static MessageDigest getMessageDigest(String algorithm) throws GeneralSecurityException {
        if (isSmAlgorithm(algorithm)) {
            return MessageDigest.getInstance(algorithm, ProviderManager.getBcProvider());
        }
        Provider provider = ProviderManager.getProvider();
        try {
            return MessageDigest.getInstance(algorithm, provider);
        } catch (GeneralSecurityException e) {
            LOGGER.error("[EncryptionSDK] Get message digest error: {}", e.getMessage());
            return MessageDigest.getInstance(algorithm, ProviderManager.getBcProvider());
        }
    }

    public static Cipher getCipher(String transformation) throws GeneralSecurityException {
        if (isSmAlgorithm(transformation)) {
            return Cipher.getInstance(transformation, ProviderManager.getBcProvider());
        }
        Provider provider = ProviderManager.getProvider();
        try {
            return Cipher.getInstance(transformation, provider);
        } catch (GeneralSecurityException e) {
            LOGGER.error("[EncryptionSDK] Get cipher error: {}", e.getMessage());
            return Cipher.getInstance(transformation, ProviderManager.getBcProvider());
        }
    }

    public static Signature getSignature(String algorithm) throws GeneralSecurityException {
        if (isSmAlgorithm(algorithm)) {
            return Signature.getInstance(algorithm, ProviderManager.getBcProvider());
        }
        Provider provider = ProviderManager.getProvider();
        try {
            return Signature.getInstance(algorithm, provider);
        } catch (GeneralSecurityException e) {
            LOGGER.error("[EncryptionSDK] Get Signature error: {}", e.getMessage());
            return Signature.getInstance(algorithm, ProviderManager.getBcProvider());
        }
    }

    public static KeyPairGenerator getKeyPairGenerator(String algorithm) throws GeneralSecurityException {
        if (isSmAlgorithm(algorithm)) {
            return KeyPairGenerator.getInstance(algorithm, ProviderManager.getBcProvider());
        }
        Provider provider = ProviderManager.getProvider();
        try {
            return KeyPairGenerator.getInstance(algorithm, provider);
        } catch (GeneralSecurityException e) {
            LOGGER.error("[EncryptionSDK] Get Key Pair error: {}", e.getMessage());
            return KeyPairGenerator.getInstance(algorithm, ProviderManager.getBcProvider());
        }
    }

    public static KeyGenerator getKeyGenerator(String algorithm) throws GeneralSecurityException {
        if (isSmAlgorithm(algorithm)) {
            return KeyGenerator.getInstance(algorithm, ProviderManager.getBcProvider());
        }
        Provider provider = ProviderManager.getProvider();
        try {
            return KeyGenerator.getInstance(algorithm, provider);
        } catch (GeneralSecurityException e) {
            LOGGER.error("[EncryptionSDK] Get Key Generator error: {}", e.getMessage());
            return KeyGenerator.getInstance(algorithm, ProviderManager.getBcProvider());
        }
    }

    public static KeyFactory getKeyFactory(String algorithm) throws GeneralSecurityException {
        if (isSmAlgorithm(algorithm)) {
            return KeyFactory.getInstance(algorithm, ProviderManager.getBcProvider());
        }
        Provider provider = ProviderManager.getProvider();
        try {
            return KeyFactory.getInstance(algorithm, provider);
        } catch (GeneralSecurityException e) {
            LOGGER.error("[EncryptionSDK] Get Key Factory error: {}", e.getMessage());
            return KeyFactory.getInstance(algorithm, ProviderManager.getBcProvider());
        }
    }

    private static boolean isSmAlgorithm(String algorithm) {
        if (algorithm == null) {
            return false;
        }
        String upper = algorithm.toUpperCase(Locale.ENGLISH);
        for (String sm : SM_ALGORITHMS) {
            if (upper.startsWith(sm)) {
                return true;
            }
        }
        return false;
    }
}
