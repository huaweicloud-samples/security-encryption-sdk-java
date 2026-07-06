package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.common.CountingOutputStream;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;

public class CountingOutputStreamTest {

    @Test
    public void testWriteInt() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CountingOutputStream cos = new CountingOutputStream(baos);
        cos.write(65);
        assertEquals(1, cos.getBytesWritten());
        cos.write(66);
        assertEquals(2, cos.getBytesWritten());
    }

    @Test
    public void testWriteByteArray() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CountingOutputStream cos = new CountingOutputStream(baos);
        byte[] data = "Hello".getBytes(StandardCharsets.UTF_8);
        cos.write(data, 0, data.length);
        assertEquals(5, cos.getBytesWritten());
    }

    @Test
    public void testWriteByteArrayWithOffset() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CountingOutputStream cos = new CountingOutputStream(baos);
        byte[] data = "HelloWorld".getBytes(StandardCharsets.UTF_8);
        cos.write(data, 0, 5);
        assertEquals(5, cos.getBytesWritten());
        cos.write(data, 5, 5);
        assertEquals(10, cos.getBytesWritten());
    }

    @Test
    public void testInitialBytesWritten() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CountingOutputStream cos = new CountingOutputStream(baos);
        assertEquals(0, cos.getBytesWritten());
    }

    @Test
    public void testMultipleWrites() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CountingOutputStream cos = new CountingOutputStream(baos);
        cos.write(1);
        cos.write(2);
        byte[] data = new byte[100];
        cos.write(data, 0, 100);
        assertEquals(102, cos.getBytesWritten());
    }
}
