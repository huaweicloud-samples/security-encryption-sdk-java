package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class EncryptRequestTest {

    @Test
    public void testDefaultConstructor() {
        EncryptRequest req = new EncryptRequest();
        assertNotNull(req.getEncryptionContext());
        assertTrue(req.getEncryptionContext().isEmpty());
        assertNull(req.getPlainText());
        assertNull(req.getPolicyId());
        assertNull(req.getKeyPolicy());
    }

    @Test
    public void testConstructorWithArgs() {
        Map<String, String> ctx = new HashMap<>();
        ctx.put("key", "value");
        byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
        EncryptRequest req = new EncryptRequest(ctx, data);
        assertEquals(1, req.getEncryptionContext().size());
        assertEquals("value", req.getEncryptionContext().get("key"));
        assertEquals(data, req.getPlainText());
    }
}
