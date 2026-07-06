package com.huawei.encyptionsdk.test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.huaweicloud.encryptionsdk.proof.AttestationDocument;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class AttestationDocumentTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    public void testBuilder() {
        AttestationDocument doc = AttestationDocument.builder()
                .ecsSignature("ecs-sig")
                .customSignature("custom-sig")
                .customPublicKey("custom-pub")
                .expireTime("2026-12-31")
                .serviceToken("token-1")
                .build();
        assertEquals("ecs-sig", doc.getEcsSignature());
        assertEquals("custom-sig", doc.getCustomSignature());
        assertEquals("custom-pub", doc.getCustomPublicKey());
        assertEquals("2026-12-31", doc.getExpireTime());
        assertEquals("token-1", doc.getServiceToken());
    }

    @Test
    public void testToStringMasksServiceToken() {
        AttestationDocument doc = AttestationDocument.builder()
                .ecsSignature("sig")
                .serviceToken("secret-token")
                .build();
        String str = doc.toString();
        assertNotNull(str);
        assertFalse(str.contains("secret-token"));
        assertTrue(str.contains("****"));
    }

    @Test
    public void testNoArgsConstructor() {
        AttestationDocument doc = new AttestationDocument();
        assertNotNull(doc);
        assertEquals(null, doc.getEcsSignature());
        assertEquals(null, doc.getServiceToken());
    }

    @Test
    public void testAllArgsConstructor() {
        AttestationDocument doc = new AttestationDocument("ecs", "custom", "pub", "expire", "token");
        assertEquals("ecs", doc.getEcsSignature());
        assertEquals("custom", doc.getCustomSignature());
        assertEquals("pub", doc.getCustomPublicKey());
        assertEquals("expire", doc.getExpireTime());
        assertEquals("token", doc.getServiceToken());
    }

    @Test
    public void testSetters() {
        AttestationDocument doc = new AttestationDocument();
        doc.setEcsSignature("e");
        doc.setCustomSignature("c");
        doc.setCustomPublicKey("p");
        doc.setExpireTime("t");
        doc.setServiceToken("s");
        assertEquals("e", doc.getEcsSignature());
        assertEquals("c", doc.getCustomSignature());
        assertEquals("p", doc.getCustomPublicKey());
        assertEquals("t", doc.getExpireTime());
        assertEquals("s", doc.getServiceToken());
    }
}
