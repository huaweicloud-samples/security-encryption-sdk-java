package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.proof.PrivateKeyDecryptCallback;
import org.junit.Assert;
import org.junit.Test;

public class PrivateKeyDecryptCallbackTest {

    @Test
    public void testDecrypt() {
        PrivateKeyDecryptCallback callback = encrypted -> "plain_" + encrypted;
        Assert.assertEquals("plain_encKey", callback.decrypt("encKey"));
    }

    @Test
    public void testDecrypt_ReturnNull() {
        PrivateKeyDecryptCallback callback = encrypted -> null;
        Assert.assertNull(callback.decrypt("encKey"));
    }

    @Test
    public void testDecrypt_EmptyInput() {
        PrivateKeyDecryptCallback callback = encrypted -> "result";
        Assert.assertEquals("result", callback.decrypt(""));
    }

    @Test
    public void testLambdaImplementation() {
        PrivateKeyDecryptCallback callback = e -> new StringBuilder(e).reverse().toString();
        Assert.assertEquals("yeke", callback.decrypt("ekey"));
    }
}
