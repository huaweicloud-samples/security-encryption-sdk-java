package com.huawei.encyptionsdk.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huaweicloud.encryptionsdk.kms.CreateKeyCapsuleRequest;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class CreateKeyCapsuleRequestTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    public void testBuilder() {
        CreateKeyCapsuleRequest req = CreateKeyCapsuleRequest.builder()
                .keyId("key-123")
                .datakeyLength(256)
                .publicKey("pub-key")
                .policyId("policy-1")
                .keyPolicy("policy-content")
                .build();
        assertEquals("key-123", req.getKeyId());
        assertEquals(256, req.getDatakeyLength());
        assertEquals("pub-key", req.getPublicKey());
        assertEquals("policy-1", req.getPolicyId());
        assertEquals("policy-content", req.getKeyPolicy());
    }
}
