package com.huawei.encyptionsdk.test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huaweicloud.encryptionsdk.log.LtsStructLogBuilder;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class LtsStructLogBuilderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode parse(String json) throws Exception {
        return MAPPER.readTree(json);
    }

    @Test
    public void testBuildEncryptStructLog_AllParams() throws Exception {
        String log = LtsStructLogBuilder.buildEncryptStructLog(
                "input.txt", 1024L, "output.enc", 2048L, "key-123", "ECS", "i-abc123");
        JsonNode node = parse(log);
        assertEquals("encrypt", node.get("operation").asText());
        assertEquals("input.txt", node.get("encryptFileName").asText());
        assertEquals("1024", node.get("encryptDataBytes").asText());
        assertEquals("output.enc", node.get("encryptOutputFileName").asText());
        assertEquals("2048", node.get("encryptOutputBytes").asText());
        assertEquals("key-123", node.get("keyId").asText());
        assertEquals("ECS", node.get("accessPointType").asText());
        assertEquals("i-abc123", node.get("instanceId").asText());
        assertTrue(node.has("timestamp"));
        assertTrue(node.has("utcTime"));
    }

    @Test
    public void testBuildEncryptStructLog_NullParams() throws Exception {
        String log = LtsStructLogBuilder.buildEncryptStructLog(
                null, null, null, null, null, null, null);
        JsonNode node = parse(log);
        assertEquals("encrypt", node.get("operation").asText());
        assertTrue(node.has("timestamp"));
        assertTrue(node.has("utcTime"));
        assertNull(node.get("encryptFileName"));
        assertNull(node.get("encryptDataBytes"));
        assertNull(node.get("keyId"));
    }

    @Test
    public void testBuildEncryptStructLog_EmptyParams() throws Exception {
        String log = LtsStructLogBuilder.buildEncryptStructLog(
                "", 0L, "", 0L, "", "", "");
        JsonNode node = parse(log);
        assertEquals("encrypt", node.get("operation").asText());
        assertNull(node.get("encryptFileName"));
        assertNull(node.get("encryptDataBytes"));
        assertNull(node.get("keyId"));
    }

    @Test
    public void testBuildEncryptStructLog_NegativeBytes() throws Exception {
        String log = LtsStructLogBuilder.buildEncryptStructLog(
                "f.txt", -1L, "f.enc", -1L, "kid", "Custom", null);
        JsonNode node = parse(log);
        assertEquals("encrypt", node.get("operation").asText());
        assertEquals("f.txt", node.get("encryptFileName").asText());
        assertEquals("f.enc", node.get("encryptOutputFileName").asText());
        assertNull(node.get("encryptDataBytes"));
        assertNull(node.get("encryptOutputBytes"));
        assertEquals("kid", node.get("keyId").asText());
    }

    @Test
    public void testBuildEncryptStructLog_NullDataBytes() throws Exception {
        String log = LtsStructLogBuilder.buildEncryptStructLog(
                "f.txt", null, "f.enc", null, "kid", "ECS", "i-123");
        JsonNode node = parse(log);
        assertEquals("kid", node.get("keyId").asText());
        assertNull(node.get("encryptDataBytes"));
        assertNull(node.get("encryptOutputBytes"));
    }

    @Test
    public void testBuildDecryptStructLog_AllParams() throws Exception {
        String log = LtsStructLogBuilder.buildDecryptStructLog(
                "output.enc", 2048L, "decrypted.txt", 1024L, "key-123", "ECS", "i-abc123");
        JsonNode node = parse(log);
        assertEquals("decrypt", node.get("operation").asText());
        assertEquals("output.enc", node.get("decryptFileName").asText());
        assertEquals("2048", node.get("decryptDataBytes").asText());
        assertEquals("decrypted.txt", node.get("decryptOutputFileName").asText());
        assertEquals("1024", node.get("decryptOutputBytes").asText());
        assertEquals("key-123", node.get("keyId").asText());
        assertEquals("ECS", node.get("accessPointType").asText());
        assertEquals("i-abc123", node.get("instanceId").asText());
    }

    @Test
    public void testBuildDecryptStructLog_NullParams() throws Exception {
        String log = LtsStructLogBuilder.buildDecryptStructLog(
                null, null, null, null, null, null, null);
        JsonNode node = parse(log);
        assertEquals("decrypt", node.get("operation").asText());
        assertNull(node.get("decryptFileName"));
        assertNull(node.get("keyId"));
    }

    @Test
    public void testBuildDecryptStructLog_EmptyParams() throws Exception {
        String log = LtsStructLogBuilder.buildDecryptStructLog(
                "", 0L, "", 0L, "", "", "");
        JsonNode node = parse(log);
        assertEquals("decrypt", node.get("operation").asText());
        assertNull(node.get("decryptFileName"));
        assertNull(node.get("keyId"));
    }

    @Test
    public void testBuildDecryptStructLog_NullDataBytes() throws Exception {
        String log = LtsStructLogBuilder.buildDecryptStructLog(
                "f.enc", null, "f.txt", null, "kid", "ECS", "i-123");
        JsonNode node = parse(log);
        assertEquals("kid", node.get("keyId").asText());
        assertNull(node.get("decryptDataBytes"));
        assertNull(node.get("decryptOutputBytes"));
    }

    @Test
    public void testBuildEncryptStructLog_WithIpAddress() throws Exception {
        String log = LtsStructLogBuilder.buildEncryptStructLog(
                "f.txt", 100L, "f.enc", 200L, "kid", "Custom", null);
        JsonNode node = parse(log);
        assertTrue(node.has("timestamp"));
        assertTrue(node.has("utcTime"));
    }

    @Test
    public void testBuildDecryptStructLog_CCEType() throws Exception {
        String log = LtsStructLogBuilder.buildDecryptStructLog(
                "f.enc", 200L, "f.txt", 100L, "kid", "CCE", "i-456");
        JsonNode node = parse(log);
        assertEquals("CCE", node.get("accessPointType").asText());
    }

    @Test
    public void testBuildStructLogSanitizesCRLF() throws Exception {
        String log = LtsStructLogBuilder.buildStructLog(
                "encrypt", "a\r\nb", 1L, "out", 2L, "kid\r\ninjected", "ECS", "i-123");
        JsonNode node = parse(log);
        assertEquals("ab", node.get("encryptFileName").asText());
        assertEquals("kidinjected", node.get("keyId").asText());
        assertFalse(log.contains("\r"));
        assertFalse(log.contains("\n"));
    }
}
