package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import org.junit.Test;

import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class HuaweiConfigTest {

    @Test
    public void Should_ok_When_StateUnderTest() {
        HuaweiConfig build = HuaweiConfig.builder().ak("2").sk("2").build();
        assertEquals("2", build.getAk());
        assertEquals("2", build.getSk());
    }

    @Test
    public void testBuilderWithAllFields() {
        KMSConfig kmsConfig = new KMSConfig("cn-north-7", "kid", "pid", "ep");
        HuaweiConfig config = HuaweiConfig.builder()
                .ak("ak")
                .sk("sk")
                .isDiscovery(true)
                .kmsConfigList(Collections.singletonList(kmsConfig))
                .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .localLogOnly(true)
                .build();
        assertEquals("ak", config.getAk());
        assertEquals("sk", config.getSk());
        assertTrue(config.isDiscovery());
        assertTrue(config.isLocalLogOnly());
        assertEquals(CryptoAlgorithm.AES_256_GCM_NOPADDING, config.getCryptoAlgorithm());
        assertNotNull(config.getKmsConfigList());
        assertEquals(1, config.getKmsConfigList().size());
        assertEquals("cn-north-7", config.getKmsConfigList().get(0).getRegion());
    }

    @Test
    public void testSetAkValid() {
        HuaweiConfig config = new HuaweiConfig();
        config.setAk("validAk");
        assertEquals("validAk", config.getAk());
    }

    @Test(expected = HuaweicloudException.class)
    public void testSetAkNull() {
        HuaweiConfig config = new HuaweiConfig();
        config.setAk(null);
    }

    @Test(expected = HuaweicloudException.class)
    public void testSetAkEmpty() {
        HuaweiConfig config = new HuaweiConfig();
        config.setAk("");
    }

    @Test
    public void testSetSkValid() {
        HuaweiConfig config = new HuaweiConfig();
        config.setSk("validSk");
        assertEquals("validSk", config.getSk());
    }

    @Test(expected = HuaweicloudException.class)
    public void testSetSkNull() {
        HuaweiConfig config = new HuaweiConfig();
        config.setSk(null);
    }

    @Test(expected = HuaweicloudException.class)
    public void testSetSkEmpty() {
        HuaweiConfig config = new HuaweiConfig();
        config.setSk("");
    }

    @Test
    public void testNoArgsConstructor() {
        HuaweiConfig config = new HuaweiConfig();
        assertNull(config.getKmsConfigList());
    }

    @Test
    public void testAllArgsConstructor() {
        KMSConfig kmsConfig = new KMSConfig("r", "k", "p", "e");
        HuaweiConfig config = new HuaweiConfig("ak", "sk", "", true,
                Collections.singletonList(kmsConfig), null, CryptoAlgorithm.AES_256_GCM_NOPADDING,
                null, null, false);
        assertEquals("ak", config.getAk());
        assertEquals("sk", config.getSk());
        assertTrue(config.isDiscovery());
        assertEquals(CryptoAlgorithm.AES_256_GCM_NOPADDING, config.getCryptoAlgorithm());
        assertNotNull(config.getKmsConfigList());
        assertEquals(1, config.getKmsConfigList().size());
        assertEquals("r", config.getKmsConfigList().get(0).getRegion());
        assertFalse(config.isLocalLogOnly());
    }
}
