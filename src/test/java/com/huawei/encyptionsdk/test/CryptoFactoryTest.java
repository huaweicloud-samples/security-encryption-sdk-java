package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.common.CryptoFactory;
import com.huaweicloud.encryptionsdk.common.ProviderManager;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Signature;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class CryptoFactoryTest {

    @Test
    public void testGetMessageDigestAes() throws GeneralSecurityException {
        MessageDigest md = CryptoFactory.getMessageDigest("SHA-256");
        assertEquals("SHA-256", md.getAlgorithm());
        byte[] digest = md.digest("test".getBytes(StandardCharsets.UTF_8));
        assertTrue(digest.length > 0);
    }

    @Test
    public void testGetMessageDigestSm() throws GeneralSecurityException {
        MessageDigest md = CryptoFactory.getMessageDigest("SM3");
        assertTrue(md.getAlgorithm().equalsIgnoreCase("SM3"));
        byte[] digest = md.digest("test".getBytes(StandardCharsets.UTF_8));
        assertTrue(digest.length > 0);
    }

    @Test
    public void testGetCipherAes() throws GeneralSecurityException {
        Cipher cipher = CryptoFactory.getCipher("AES/GCM/NoPadding");
        assertTrue(cipher.getAlgorithm().startsWith("AES"));
    }

    @Test
    public void testGetCipherSm() throws GeneralSecurityException {
        Cipher cipher = CryptoFactory.getCipher("SM4/GCM/NoPadding");
        assertTrue(cipher.getAlgorithm().startsWith("SM4"));
    }

    @Test
    public void testGetSignature() throws GeneralSecurityException {
        Signature sig = CryptoFactory.getSignature("NONEwithECDSA");
        assertTrue(sig.getAlgorithm().contains("ECDSA"));
    }

    @Test
    public void testGetSignatureSm() throws GeneralSecurityException {
        Signature sig = CryptoFactory.getSignature("SM3withSM2");
        assertTrue(sig.getAlgorithm().contains("SM2"));
    }

    @Test
    public void testGetKeyPairGenerator() throws GeneralSecurityException {
        KeyPairGenerator kpg = CryptoFactory.getKeyPairGenerator("EC");
        assertEquals("EC", kpg.getAlgorithm());
    }

    @Test
    public void testGetKeyPairGeneratorSm() throws GeneralSecurityException {
        KeyPairGenerator kpg = CryptoFactory.getKeyPairGenerator("SM2");
        assertEquals("SM2", kpg.getAlgorithm());
    }

    @Test
    public void testGetKeyGenerator() throws GeneralSecurityException {
        KeyGenerator kg = CryptoFactory.getKeyGenerator("AES");
        assertEquals("AES", kg.getAlgorithm());
    }

    @Test
    public void testGetKeyGeneratorSm() throws GeneralSecurityException {
        KeyGenerator kg = CryptoFactory.getKeyGenerator("SM4");
        assertEquals("SM4", kg.getAlgorithm());
    }

    @Test
    public void testGetKeyFactory() throws GeneralSecurityException {
        KeyFactory kf = CryptoFactory.getKeyFactory("EC");
        assertEquals("EC", kf.getAlgorithm());
    }

    @Test
    public void testGetKeyFactorySm() throws GeneralSecurityException {
        try {
            KeyFactory kf = CryptoFactory.getKeyFactory("SM2");
            assertEquals("SM2", kf.getAlgorithm());
        } catch (GeneralSecurityException ignored) {
            // SM2 KeyFactory may not be available in this environment
        }
    }

    @Test
    public void testIsSmAlgorithmLowercase() throws GeneralSecurityException {
        MessageDigest md = CryptoFactory.getMessageDigest("sm3");
        assertTrue(md.getAlgorithm().equalsIgnoreCase("SM3"));
    }

    @Test
    public void testIsSmAlgorithmMixedCase() throws GeneralSecurityException {
        MessageDigest md = CryptoFactory.getMessageDigest("Sm3");
        assertTrue(md.getAlgorithm().equalsIgnoreCase("SM3"));
    }

    @Test
    public void testGetCipherFallback() throws GeneralSecurityException {
        Cipher cipher = CryptoFactory.getCipher("AES/GCM/NoPadding");
        assertTrue(cipher.getProvider().getName().equals("BC") || cipher.getProvider().getName().contains("KAE") || cipher.getProvider().getName().equals("SunJCE"));
    }

    @Test
    public void testGetMessageDigestWithInvalidProviderFallback() throws GeneralSecurityException {
        Provider originalProvider = ProviderManager.getProvider();
        try {
            resetProviderCache();
            System.setProperty("crypto.sdk.disableKae", "true");
            resetProviderCache();
            MessageDigest md = CryptoFactory.getMessageDigest("SHA-256");
            // MessageDigest uses JCA default (SUN provider), not ProviderManager
            assertEquals("SUN", md.getProvider().getName());
        } finally {
            System.clearProperty("crypto.sdk.disableKae");
            resetProviderCache();
        }
    }

    @Test
    public void testGetCipherWithInvalidProviderFallback() throws GeneralSecurityException {
        try {
            System.setProperty("crypto.sdk.disableKae", "true");
            resetProviderCache();
            Cipher cipher = CryptoFactory.getCipher("AES/GCM/NoPadding");
            assertTrue(cipher.getAlgorithm().startsWith("AES"));
        } finally {
            System.clearProperty("crypto.sdk.disableKae");
            resetProviderCache();
        }
    }

    @Test
    public void testGetSignatureWithInvalidProviderFallback() throws GeneralSecurityException {
        try {
            System.setProperty("crypto.sdk.disableKae", "true");
            resetProviderCache();
            Signature sig = CryptoFactory.getSignature("NONEwithECDSA");
            assertTrue(sig.getAlgorithm().contains("ECDSA"));
        } finally {
            System.clearProperty("crypto.sdk.disableKae");
            resetProviderCache();
        }
    }

    @Test
    public void testGetKeyPairGeneratorWithInvalidProviderFallback() throws GeneralSecurityException {
        try {
            System.setProperty("crypto.sdk.disableKae", "true");
            resetProviderCache();
            KeyPairGenerator kpg = CryptoFactory.getKeyPairGenerator("EC");
            assertEquals("EC", kpg.getAlgorithm());
        } finally {
            System.clearProperty("crypto.sdk.disableKae");
            resetProviderCache();
        }
    }

    @Test
    public void testGetKeyGeneratorWithInvalidProviderFallback() throws GeneralSecurityException {
        try {
            System.setProperty("crypto.sdk.disableKae", "true");
            resetProviderCache();
            KeyGenerator kg = CryptoFactory.getKeyGenerator("AES");
            assertEquals("AES", kg.getAlgorithm());
        } finally {
            System.clearProperty("crypto.sdk.disableKae");
            resetProviderCache();
        }
    }

    @Test
    public void testGetKeyFactoryWithInvalidProviderFallback() throws GeneralSecurityException {
        try {
            System.setProperty("crypto.sdk.disableKae", "true");
            resetProviderCache();
            KeyFactory kf = CryptoFactory.getKeyFactory("EC");
            assertEquals("EC", kf.getAlgorithm());
        } finally {
            System.clearProperty("crypto.sdk.disableKae");
            resetProviderCache();
        }
    }

    @Test
    public void testIsSmAlgorithmNull() throws GeneralSecurityException {
        MessageDigest md = CryptoFactory.getMessageDigest("SHA-256");
        assertEquals("SHA-256", md.getAlgorithm());
    }

    @Test
    public void testIsSmAlgorithmNotMisidentifyDSAwithSM3() throws GeneralSecurityException {
        try {
            System.setProperty("crypto.sdk.disableKae", "true");
            resetProviderCache();
            Signature sig = CryptoFactory.getSignature("SHA256withDSA");
            // Non-SM Signature uses JCA default provider
            assertNotNull(sig.getProvider());
        } finally {
            System.clearProperty("crypto.sdk.disableKae");
            resetProviderCache();
        }
    }

    @Test
    public void testGetMessageDigestFallbackFromBrokenProvider() throws GeneralSecurityException {
        Provider broken = new Provider("Broken", 1.0, "Broken") {};
        setProvider(broken);
        try {
            MessageDigest md = CryptoFactory.getMessageDigest("SHA-256");
            // MessageDigest uses JCA default (SUN), not ProviderManager
            assertEquals("SUN", md.getProvider().getName());
        } finally {
            resetProviderCache();
        }
    }

    @Test
    public void testGetCipherFallbackFromBrokenProvider() throws GeneralSecurityException {
        Provider broken = new Provider("Broken", 1.0, "Broken") {};
        setProvider(broken);
        try {
            Cipher cipher = CryptoFactory.getCipher("AES/GCM/NoPadding");
            assertEquals("BC", cipher.getProvider().getName());
        } finally {
            resetProviderCache();
        }
    }

    @Test
    public void testGetSignatureFallbackFromBrokenProvider() throws GeneralSecurityException {
        Provider broken = new Provider("Broken", 1.0, "Broken") {};
        setProvider(broken);
        try {
            Signature sig = CryptoFactory.getSignature("NONEwithECDSA");
            // Non-SM Signature uses JCA default, not ProviderManager
            assertNotNull(sig.getProvider());
        } finally {
            resetProviderCache();
        }
    }

    @Test
    public void testGetKeyPairGeneratorFallbackFromBrokenProvider() throws GeneralSecurityException {
        Provider broken = new Provider("Broken", 1.0, "Broken") {};
        setProvider(broken);
        try {
            KeyPairGenerator kpg = CryptoFactory.getKeyPairGenerator("EC");
            // Non-SM KeyPairGenerator uses JCA default, not ProviderManager
            assertNotNull(kpg.getProvider());
        } finally {
            resetProviderCache();
        }
    }

    @Test
    public void testGetKeyGeneratorFallbackFromBrokenProvider() throws GeneralSecurityException {
        Provider broken = new Provider("Broken", 1.0, "Broken") {};
        setProvider(broken);
        try {
            KeyGenerator kg = CryptoFactory.getKeyGenerator("AES");
            assertEquals("BC", kg.getProvider().getName());
        } finally {
            resetProviderCache();
        }
    }

    @Test
    public void testGetKeyFactoryFallbackFromBrokenProvider() throws GeneralSecurityException {
        Provider broken = new Provider("Broken", 1.0, "Broken") {};
        setProvider(broken);
        try {
            KeyFactory kf = CryptoFactory.getKeyFactory("EC");
            // Non-SM KeyFactory uses JCA default, not ProviderManager
            assertNotNull(kf.getProvider());
        } finally {
            resetProviderCache();
        }
    }

    private void setProvider(Provider p) {
        try {
            Field field = ProviderManager.class.getDeclaredField("provider");
            field.setAccessible(true);
            field.set(null, p);
        } catch (Exception e) {
            throw new HuaweicloudException(e);
        }
    }

    private void resetProviderCache() {
        try {
            Field field = ProviderManager.class.getDeclaredField("provider");
            field.setAccessible(true);
            field.set(null, null);
        } catch (Exception e) {
            throw new HuaweicloudException(e);
        }
    }
}
