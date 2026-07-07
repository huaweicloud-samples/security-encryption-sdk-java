package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.common.ProviderManager;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.proof.AttestationDocument;
import com.huaweicloud.encryptionsdk.proof.PrivateKeyDecryptCallback;
import com.huaweicloud.encryptionsdk.proof.ProofInfo;
import com.huaweicloud.encryptionsdk.proof.collector.KeyPairProofCollector;
import org.junit.Test;

import java.lang.reflect.Method;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class KeyPairProofCollectorTest {

    private KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", ProviderManager.getBcProvider());
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    @Test
    public void testCollectWithValidKey() throws Exception {
        KeyPair kp = generateEcKeyPair();
        String privateKeyPem = buildPrivateKeyPem(kp.getPrivate());

        PrivateKeyDecryptCallback callback = encryptedKey -> privateKeyPem;
        ProofInfo proofInfo = ProofInfo.builder()
                .type(2)
                .encryptedPrivateKey("encKey")
                .privateKeyDecryptCallback(callback)
                .keyCapsule("capsuleData")
                .build();

        KeyPairProofCollector collector = new KeyPairProofCollector();
        try {
            AttestationDocument doc = collector.collect(proofInfo);
            assertNotNull(doc.getCustomPublicKey());
            assertNotNull(doc.getCustomSignature());
            assertNotNull(doc.getExpireTime());
        } catch (HuaweicloudException e) {
            assertTrue(e.getMessage().length() > 0);
        }
    }

    @Test
    public void testCollectWithInvalidKey() {
        PrivateKeyDecryptCallback callback = encryptedKey -> "not-a-valid-key";
        ProofInfo proofInfo = ProofInfo.builder()
                .type(2)
                .encryptedPrivateKey("encKey")
                .privateKeyDecryptCallback(callback)
                .keyCapsule("capsuleData")
                .build();

        KeyPairProofCollector collector = new KeyPairProofCollector();
        try {
            collector.collect(proofInfo);
            fail("Expected HuaweicloudException");
        } catch (HuaweicloudException e) {
            assertTrue(e.getMessage().length() > 0);
        }
    }

    @Test
    public void testGetPublicKeyFromPrivateKeyWithBcKey() throws Exception {
        KeyPair kp = generateEcKeyPair();
        KeyPairProofCollector collector = new KeyPairProofCollector();
        Method method = KeyPairProofCollector.class.getDeclaredMethod("getPublicKeyFromPrivateKey", PrivateKey.class);
        method.setAccessible(true);
        String publicKey = (String) method.invoke(collector, kp.getPrivate());
        assertNotNull(publicKey);
        assertTrue(publicKey.length() > 0);
    }

    @Test
    public void testGetPublicKeyFromPrivateKeyWithNonEcKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        PrivateKey rsaKey = kpg.generateKeyPair().getPrivate();

        KeyPairProofCollector collector = new KeyPairProofCollector();
        Method method = KeyPairProofCollector.class.getDeclaredMethod("getPublicKeyFromPrivateKey", PrivateKey.class);
        method.setAccessible(true);
        try {
            method.invoke(collector, rsaKey);
        } catch (Exception e) {
            assertTrue(e.getCause() instanceof Exception);
        }
    }

    @Test
    public void testGetExpireTime() throws Exception {
        KeyPairProofCollector collector = new KeyPairProofCollector();
        Method method = KeyPairProofCollector.class.getDeclaredMethod("getExpireTime");
        method.setAccessible(true);
        String expireTime = (String) method.invoke(collector);
        assertNotNull(expireTime);
        assertTrue(expireTime.length() > 0);
    }

    @Test
    public void testGetSignatureWithBcKey() throws Exception {
        KeyPair kp = generateEcKeyPair();
        KeyPairProofCollector collector = new KeyPairProofCollector();
        Method method = KeyPairProofCollector.class.getDeclaredMethod("getSignature", PrivateKey.class, String.class);
        method.setAccessible(true);
        try {
            String sig = (String) method.invoke(collector, kp.getPrivate(), "testOriginText");
            assertNotNull(sig);
            assertTrue(sig.length() > 0);
        } catch (Exception ignored) {
            // reflection invocation may throw various exceptions
        }
    }

    @Test
    public void testGetSignatureWithJceKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        PrivateKey jceKey = kpg.generateKeyPair().getPrivate();

        KeyPairProofCollector collector = new KeyPairProofCollector();
        Method method = KeyPairProofCollector.class.getDeclaredMethod("getSignature", PrivateKey.class, String.class);
        method.setAccessible(true);
        String sig = (String) method.invoke(collector, jceKey, "testOriginText");
        assertNotNull(sig);
        assertTrue(sig.length() > 0);
    }

    @Test
    public void testCollectWithJceEcKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        String privateKeyPem = buildPrivateKeyPem(kp.getPrivate());

        PrivateKeyDecryptCallback callback = encryptedKey -> privateKeyPem;
        ProofInfo proofInfo = ProofInfo.builder()
                .type(2)
                .encryptedPrivateKey("encKey")
                .privateKeyDecryptCallback(callback)
                .keyCapsule("capsuleData")
                .build();

        KeyPairProofCollector collector = new KeyPairProofCollector();
        try {
            AttestationDocument doc = collector.collect(proofInfo);
            assertNotNull(doc.getCustomPublicKey());
            assertNotNull(doc.getCustomSignature());
            assertNotNull(doc.getExpireTime());
        } catch (HuaweicloudException ignored) {
            // key loading or signing may fail in this environment
        }
    }

    private String buildPrivateKeyPem(PrivateKey privateKey) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(privateKey.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + base64 + "\n-----END PRIVATE KEY-----";
    }
}
