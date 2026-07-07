package com.huawei.encyptionsdk.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huaweicloud.encryptionsdk.kms.DecryptKeyCapsuleResponse;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class DecryptKeyCapsuleResponseTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    public void testBuilder() {
        DecryptKeyCapsuleResponse resp = DecryptKeyCapsuleResponse.builder()
                .keyId("key-1")
                .datakey("dk")
                .datakeyCipher("cipher")
                .instanceId("inst-1")
                .build();
        assertEquals("key-1", resp.getKeyId());
        assertEquals("dk", resp.getDatakey());
        assertEquals("cipher", resp.getDatakeyCipher());
        assertEquals("inst-1", resp.getInstanceId());
    }

    @Test
    public void testJsonWithoutInstanceId() throws Exception {
        String json = "{\"key_id\":\"key-1\",\"datakey\":\"dk\",\"datakey_cipher\":\"cipher\"}";
        DecryptKeyCapsuleResponse resp = MAPPER.readValue(json, DecryptKeyCapsuleResponse.class);
        assertEquals("key-1", resp.getKeyId());
        assertNull(resp.getInstanceId());
    }
}
