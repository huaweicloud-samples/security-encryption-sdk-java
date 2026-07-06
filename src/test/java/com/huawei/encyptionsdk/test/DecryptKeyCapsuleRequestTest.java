package com.huawei.encyptionsdk.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huaweicloud.encryptionsdk.kms.DecryptKeyCapsuleRequest;
import com.huaweicloud.encryptionsdk.proof.AttestationDocument;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class DecryptKeyCapsuleRequestTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    public void testBuilder() {
        AttestationDocument doc = AttestationDocument.builder()
                .ecsSignature("sig")
                .serviceToken("token")
                .build();
        DecryptKeyCapsuleRequest req = DecryptKeyCapsuleRequest.builder()
                .keyId("key-1")
                .datakeyCapsule("capsule")
                .attestationDocument(doc)
                .build();
        assertEquals("key-1", req.getKeyId());
        assertEquals("capsule", req.getDatakeyCapsule());
        assertEquals("sig", req.getAttestationDocument().getEcsSignature());
    }
}
