package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.model.CipherHeader;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class CryptoResultTest {

    @Test
    public void testTwoArgConstructor() {
        SecretKey key = new SecretKeySpec(new byte[16], "AES");
        CipherHeader header = new CipherHeader();
        CryptoResult<byte[]> result = new CryptoResult<>(new byte[]{1, 2, 3}, header);
        assertNotNull(result.getResult());
        assertNotNull(result.getHeaders());
        assertEquals(0, result.getDataLength());
    }

    @Test
    public void testThreeArgConstructor() {
        SecretKey key = new SecretKeySpec(new byte[16], "AES");
        CipherHeader header = new CipherHeader();
        CryptoResult<byte[]> result = new CryptoResult<>(new byte[]{1, 2, 3}, header, 100L);
        assertNotNull(result.getResult());
        assertNotNull(result.getHeaders());
        assertEquals(100L, result.getDataLength());
    }

    @Test
    public void testSettersAndGetters() {
        CipherHeader header = new CipherHeader();
        CryptoResult<String> result = new CryptoResult<>("initial", header);
        assertEquals("initial", result.getResult());

        result.setResult("updated");
        assertEquals("updated", result.getResult());

        CipherHeader newHeader = new CipherHeader();
        result.setHeaders(newHeader);
        assertEquals(newHeader, result.getHeaders());
    }

    @Test
    public void testNullResult() {
        CryptoResult<String> result = new CryptoResult<>(null, new CipherHeader());
        assertNull(result.getResult());
    }
}
