package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.model.KeyCapsule;
import org.junit.Assert;
import org.junit.Test;

public class KeyCapsuleTest {

    @Test
    public void testBuilder() {
        KeyCapsule capsule = KeyCapsule.builder()
                .keyId("key-123")
                .datakeyCapsule("capsule-data")
                .accessPointType(2)
                .build();

        Assert.assertEquals("key-123", capsule.getKeyId());
        Assert.assertEquals("capsule-data", capsule.getDatakeyCapsule());
        Assert.assertEquals(2, capsule.getAccessPointType());
    }

    @Test
    public void testSetterGetter() {
        KeyCapsule capsule = new KeyCapsule();
        capsule.setKeyId("key-456");
        capsule.setDatakeyCapsule("data");
        capsule.setAccessPointType(1);

        Assert.assertEquals("key-456", capsule.getKeyId());
        Assert.assertEquals("data", capsule.getDatakeyCapsule());
        Assert.assertEquals(1, capsule.getAccessPointType());
    }

    @Test
    public void testNoArgsConstructor() {
        KeyCapsule capsule = new KeyCapsule();
        Assert.assertNotNull(capsule);
        Assert.assertNull(capsule.getKeyId());
        Assert.assertNull(capsule.getDatakeyCapsule());
        Assert.assertEquals(0, capsule.getAccessPointType());
    }

    @Test
    public void testAllArgsConstructor() {
        KeyCapsule capsule = new KeyCapsule("kid", "dc", 3, "ecsId");
        Assert.assertEquals("kid", capsule.getKeyId());
        Assert.assertEquals("dc", capsule.getDatakeyCapsule());
        Assert.assertEquals(3, capsule.getAccessPointType());
        Assert.assertEquals("ecsId", capsule.getInstanceId());
    }
}
