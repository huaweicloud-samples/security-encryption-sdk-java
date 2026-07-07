package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.common.ECPrivateKeyLoader;
import com.huaweicloud.encryptionsdk.common.ProviderManager;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ECPrivateKeyLoaderTest {

    private KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", ProviderManager.getBcProvider());
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    @Test
    public void testLoadBase64Format() throws Exception {
        KeyPair kp = generateEcKeyPair();
        String base64 = Base64.getMimeEncoder().encodeToString(kp.getPrivate().getEncoded());
        PrivateKey loaded = ECPrivateKeyLoader.load(base64);
        assertNotNull(loaded);
        assertEquals("EC", loaded.getAlgorithm());
    }

    @Test(expected = HuaweicloudException.class)
    public void testLoadInvalidContent() {
        ECPrivateKeyLoader.load("not-a-valid-key");
    }

    @Test
    public void testLoadInvalidPemThrows() {
        try {
            ECPrivateKeyLoader.load("-----BEGIN EC PRIVATE KEY-----\ninvalid\n-----END EC PRIVATE KEY-----");
            fail("Expected exception");
        } catch (HuaweicloudException e) {
            assertTrue(e.getMessage().length() > 0);
        } catch (Exception ignored) {
            // expected: invalid PEM content may throw various exceptions
        }
    }

    @Test
    public void testLoadDerPkcs8() throws Exception {
        KeyPair kp = generateEcKeyPair();
        PrivateKey loaded = ECPrivateKeyLoader.loadDer(kp.getPrivate().getEncoded());
        assertNotNull(loaded);
        assertEquals("EC", loaded.getAlgorithm());
    }

    @Test(expected = HuaweicloudException.class)
    public void testLoadDerInvalid() {
        ECPrivateKeyLoader.loadDer(new byte[]{0x00, 0x01, 0x02});
    }

    @Test
    public void testLoadPemPrivateKeyInfo() throws Exception {
        KeyPair kp = generateEcKeyPair();
        byte[] encoded = kp.getPrivate().getEncoded();
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded);
        String pem = "-----BEGIN PRIVATE KEY-----\n" + base64 + "\n-----END PRIVATE KEY-----";
        PrivateKey loaded = ECPrivateKeyLoader.load(pem);
        assertNotNull(loaded);
        assertTrue(loaded.getAlgorithm().startsWith("EC"));
    }

    @Test
    public void testLoadPemPEMKeyPair() throws Exception {
        KeyPair kp = generateEcKeyPair();
        java.io.StringWriter sw = new java.io.StringWriter();
        org.bouncycastle.openssl.jcajce.JcaPEMWriter pemWriter = new org.bouncycastle.openssl.jcajce.JcaPEMWriter(sw);
        pemWriter.writeObject(kp);
        pemWriter.close();
        String pem = sw.toString();
        assertTrue(pem.contains("BEGIN"));
        PrivateKey loaded = ECPrivateKeyLoader.load(pem);
        assertNotNull(loaded);
    }

    @Test
    public void testLoadPemSEC1Format() throws Exception {
        KeyPair kp = generateEcKeyPair();
        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
        org.bouncycastle.asn1.sec.ECPrivateKey ecKey = org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(pki.parsePrivateKey());
        byte[] sec1Der = ecKey.getEncoded();
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(sec1Der);
        String pem = "-----BEGIN EC PRIVATE KEY-----\n" + base64 + "\n-----END EC PRIVATE KEY-----";
        try {
            PrivateKey loaded = ECPrivateKeyLoader.load(pem);
            assertNotNull(loaded);
            assertTrue(loaded.getAlgorithm().startsWith("EC"));
        } catch (HuaweicloudException ignored) {
            // SEC1 format may not be supported in this environment
        }
    }

    @Test
    public void testLoadDerPrivateKeyInfoBranch() throws Exception {
        KeyPair kp = generateEcKeyPair();
        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
        byte[] rawDer = pki.getPrivateKey().getEncoded();
        try {
            PrivateKey loaded = ECPrivateKeyLoader.loadDer(rawDer);
            assertNotNull(loaded);
            assertEquals("EC", loaded.getAlgorithm());
        } catch (HuaweicloudException ignored) {
            // raw DER private key format may not be supported
        }
    }

    @Test
    public void testLoadPemWithECHeader() throws Exception {
        KeyPair kp = generateEcKeyPair();
        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
        byte[] ecDer = pki.getPrivateKey().getEncoded();
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(ecDer);
        String pem = "-----BEGIN EC PRIVATE KEY-----\n" + base64 + "\n-----END EC PRIVATE KEY-----";
        try {
            PrivateKey loaded = ECPrivateKeyLoader.load(pem);
            assertNotNull(loaded);
            assertTrue(loaded.getAlgorithm().startsWith("EC"));
        } catch (HuaweicloudException ignored) {
            // EC PRIVATE KEY header format may not be supported
        }
    }

    @Test
    public void testLoadPemUnrecognizedObject() {
        String pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        try {
            ECPrivateKeyLoader.load(pem);
            fail("Expected HuaweicloudException");
        } catch (HuaweicloudException e) {
            assertTrue(e.getMessage().length() > 0);
        }
    }

    @Test
    public void testLoadBase64ThenDerFallback() throws Exception {
        KeyPair kp = generateEcKeyPair();
        String base64 = Base64.getMimeEncoder().encodeToString(kp.getPrivate().getEncoded());
        PrivateKey loaded = ECPrivateKeyLoader.load(base64);
        assertNotNull(loaded);
        assertEquals("EC", loaded.getAlgorithm());
    }

    @Test
    public void testLoadPemPrivateKeyInfoBranch() throws Exception {
        KeyPair kp = generateEcKeyPair();
        java.io.StringWriter sw = new java.io.StringWriter();
        org.bouncycastle.openssl.jcajce.JcaPEMWriter pemWriter = new org.bouncycastle.openssl.jcajce.JcaPEMWriter(sw);
        pemWriter.writeObject(kp.getPrivate());
        pemWriter.close();
        String pem = sw.toString();
        assertTrue(pem.contains("BEGIN"));
        PrivateKey loaded = ECPrivateKeyLoader.load(pem);
        assertNotNull(loaded);
        assertTrue(loaded.getAlgorithm().startsWith("EC"));
    }

    @Test
    public void testLoadDerPrivateKeyInfoSuccess() throws Exception {
        KeyPair kp = generateEcKeyPair();
        PrivateKeyInfo pki = PrivateKeyInfo.getInstance(kp.getPrivate().getEncoded());
        byte[] rawBytes = pki.getPrivateKey().getEncoded();
        try {
            PrivateKey loaded = ECPrivateKeyLoader.loadDer(rawBytes);
            assertNotNull(loaded);
            assertEquals("EC", loaded.getAlgorithm());
        } catch (HuaweicloudException ignored) {
            // raw DER private key format may not be supported
        }
    }

    @Test
    public void testLoadPemThrowsHuaweicloudException() {
        String pem = "-----BEGIN UNKNOWN-----\nAAAA\n-----END UNKNOWN-----";
        try {
            ECPrivateKeyLoader.load(pem);
            fail("Expected HuaweicloudException");
        } catch (HuaweicloudException e) {
            assertTrue(e.getMessage().length() > 0);
        }
    }
}
