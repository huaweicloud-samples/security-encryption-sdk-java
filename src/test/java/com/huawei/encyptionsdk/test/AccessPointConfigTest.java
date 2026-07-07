package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.model.AccessPointConfig;
import com.huaweicloud.encryptionsdk.proof.PrivateKeyDecryptCallback;
import org.junit.Assert;
import org.junit.Test;

public class AccessPointConfigTest {

    @Test
    public void testBuilder() {
        PrivateKeyDecryptCallback callback = encrypted -> "decrypted";
        AccessPointConfig config = AccessPointConfig.builder()
                .type(2)
                .encryptedPrivateKey("encryptedKey")
                .privateKeyDecryptCallback(callback)
                .serviceAccount("my-sa")
                .build();

        Assert.assertEquals(2, config.getType());
        Assert.assertEquals("encryptedKey", config.getEncryptedPrivateKey());
        Assert.assertEquals(callback, config.getPrivateKeyDecryptCallback());
        Assert.assertEquals("my-sa", config.getServiceAccount());
    }

    @Test
    public void testBuilder_WithoutServiceAccount() {
        AccessPointConfig config = AccessPointConfig.builder()
                .type(1)
                .build();

        Assert.assertEquals(1, config.getType());
        Assert.assertNull(config.getServiceAccount());
        Assert.assertNull(config.getEncryptedPrivateKey());
        Assert.assertNull(config.getPrivateKeyDecryptCallback());
    }

    @Test
    public void testSetterGetter() {
        AccessPointConfig config = new AccessPointConfig();
        config.setType(3);
        config.setEncryptedPrivateKey("key");
        config.setServiceAccount("sa");

        Assert.assertEquals(3, config.getType());
        Assert.assertEquals("key", config.getEncryptedPrivateKey());
        Assert.assertEquals("sa", config.getServiceAccount());
    }

    @Test
    public void testNoArgsConstructor() {
        AccessPointConfig config = new AccessPointConfig();
        Assert.assertEquals(0, config.getType());
    }

    @Test
    public void testAllArgsConstructor() {
        PrivateKeyDecryptCallback callback = encrypted -> "plain";
        AccessPointConfig config = new AccessPointConfig(2, "encKey", callback, "sa");
        Assert.assertEquals(2, config.getType());
        Assert.assertEquals("encKey", config.getEncryptedPrivateKey());
        Assert.assertEquals(callback, config.getPrivateKeyDecryptCallback());
        Assert.assertEquals("sa", config.getServiceAccount());
    }

    @Test
    public void testCallbackInvocation() {
        PrivateKeyDecryptCallback callback = encrypted -> "plain:" + encrypted;
        AccessPointConfig config = AccessPointConfig.builder()
                .privateKeyDecryptCallback(callback)
                .build();
        Assert.assertEquals("plain:enc", config.getPrivateKeyDecryptCallback().decrypt("enc"));
    }
}
