package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.proof.ProofInfo;
import com.huaweicloud.encryptionsdk.proof.PrivateKeyDecryptCallback;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class ProofInfoTest {

    @Test
    public void testBuilder() {
        PrivateKeyDecryptCallback callback = key -> "decrypted";
        ProofInfo info = ProofInfo.builder()
                .type(2)
                .encryptedPrivateKey("encKey")
                .privateKeyDecryptCallback(callback)
                .keyCapsule("capsule")
                .serviceAccount("sa")
                .build();
        assertEquals(2, info.getType());
        assertEquals("encKey", info.getEncryptedPrivateKey());
        assertEquals(callback, info.getPrivateKeyDecryptCallback());
        assertEquals("capsule", info.getKeyCapsule());
        assertEquals("sa", info.getServiceAccount());
    }

    @Test
    public void testNoArgsConstructor() {
        ProofInfo info = new ProofInfo();
        assertNotNull(info);
        assertEquals(0, info.getType());
        assertNull(info.getEncryptedPrivateKey());
        assertNull(info.getPrivateKeyDecryptCallback());
        assertNull(info.getKeyCapsule());
        assertNull(info.getServiceAccount());
    }

    @Test
    public void testAllArgsConstructor() {
        PrivateKeyDecryptCallback callback = key -> "dec";
        ProofInfo info = new ProofInfo(1, "enc", callback, "cap", "sa");
        assertEquals(1, info.getType());
        assertEquals("enc", info.getEncryptedPrivateKey());
        assertEquals(callback, info.getPrivateKeyDecryptCallback());
        assertEquals("cap", info.getKeyCapsule());
        assertEquals("sa", info.getServiceAccount());
    }

    @Test
    public void testSetters() {
        ProofInfo info = new ProofInfo();
        info.setType(3);
        info.setEncryptedPrivateKey("ek");
        info.setKeyCapsule("kc");
        info.setServiceAccount("svc");
        assertEquals(3, info.getType());
        assertEquals("ek", info.getEncryptedPrivateKey());
        assertEquals("kc", info.getKeyCapsule());
        assertEquals("svc", info.getServiceAccount());
    }
}
