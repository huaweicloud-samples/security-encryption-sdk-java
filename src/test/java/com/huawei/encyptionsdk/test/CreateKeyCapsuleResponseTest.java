package com.huawei.encyptionsdk.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huaweicloud.encryptionsdk.kms.CreateKeyCapsuleResponse;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class CreateKeyCapsuleResponseTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    public void testBuilder() {
        CreateKeyCapsuleResponse resp = CreateKeyCapsuleResponse.builder()
                .keyId("key-1")
                .datakeyCipher("cipher")
                .datakey("dk")
                .datakeyCapsule("capsule")
                .build();
        assertEquals("key-1", resp.getKeyId());
        assertEquals("cipher", resp.getDatakeyCipher());
        assertEquals("dk", resp.getDatakey());
        assertEquals("capsule", resp.getDatakeyCapsule());
    }
}
