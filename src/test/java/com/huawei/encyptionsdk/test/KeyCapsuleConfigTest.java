package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.model.AccessPointConfig;
import com.huaweicloud.encryptionsdk.model.KeyCapsuleConfig;
import org.junit.Assert;
import org.junit.Test;

public class KeyCapsuleConfigTest {

    @Test
    public void testBuilder() {
        AccessPointConfig apConfig = AccessPointConfig.builder().type(2).build();
        KeyCapsuleConfig config = KeyCapsuleConfig.builder()
                .region("cn-north-7")
                .defaultPolicyId("policy-123")
                .defaultKeyPolicy("{\"version\":\"v1.0\"}")
                .accessPointConfig(apConfig)
                .build();

        Assert.assertEquals("cn-north-7", config.getRegion());
        Assert.assertEquals("policy-123", config.getDefaultPolicyId());
        Assert.assertEquals("{\"version\":\"v1.0\"}", config.getDefaultKeyPolicy());
        Assert.assertEquals(apConfig, config.getAccessPointConfig());
    }

    @Test
    public void testSetterGetter() {
        KeyCapsuleConfig config = new KeyCapsuleConfig();
        config.setRegion("cn-south-1");
        config.setDefaultPolicyId("pid");
        config.setDefaultKeyPolicy("policy");
        config.setAccessPointConfig(null);

        Assert.assertEquals("cn-south-1", config.getRegion());
        Assert.assertEquals("pid", config.getDefaultPolicyId());
        Assert.assertEquals("policy", config.getDefaultKeyPolicy());
        Assert.assertNull(config.getAccessPointConfig());
    }

    @Test
    public void testNoArgsConstructor() {
        KeyCapsuleConfig config = new KeyCapsuleConfig();
        Assert.assertNull(config.getRegion());
    }

    @Test
    public void testAllArgsConstructor() {
        AccessPointConfig apConfig = new AccessPointConfig();
        KeyCapsuleConfig config = new KeyCapsuleConfig("r", "pid", "kp", apConfig);
        Assert.assertEquals("r", config.getRegion());
        Assert.assertEquals("pid", config.getDefaultPolicyId());
        Assert.assertEquals("kp", config.getDefaultKeyPolicy());
        Assert.assertEquals(apConfig, config.getAccessPointConfig());
    }
}
