package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.CiphertextDataKey;
import com.huaweicloud.encryptionsdk.model.KeyCapsule;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class DataKeyMaterialsTest {

    @Test
    public void testDefaultConstructor() {
        DataKeyMaterials materials = new DataKeyMaterials();
        assertNull(materials.getPlaintextDataKey());
        assertNotNull(materials.getCiphertextDataKeys());
        assertTrue(materials.getCiphertextDataKeys().isEmpty());
        assertNotNull(materials.getEncryptionContexts());
        assertTrue(materials.getEncryptionContexts().isEmpty());
        assertNull(materials.getCryptoAlgorithm());
        assertNull(materials.getKeyCapsule());
        assertNull(materials.getPolicyId());
        assertNull(materials.getKeyPolicy());
    }

    @Test
    public void testSettersAndGetters() {
        DataKeyMaterials materials = new DataKeyMaterials();

        materials.setPlaintextDataKey(new SecretKeySpec(new byte[16], "AES"));
        assertNotNull(materials.getPlaintextDataKey());

        List<CiphertextDataKey> cdks = new ArrayList<>();
        cdks.add(new CiphertextDataKey(new byte[]{1, 2, 3}, new KMSConfig("region", "keyId", "projectId")));
        materials.setCiphertextDataKeys(cdks);
        assertEquals(1, materials.getCiphertextDataKeys().size());

        Map<String, String> context = new HashMap<>();
        context.put("key", "value");
        materials.setEncryptionContexts(context);
        assertEquals("value", materials.getEncryptionContexts().get("key"));

        materials.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        assertEquals(CryptoAlgorithm.AES_256_GCM_NOPADDING, materials.getCryptoAlgorithm());

        KeyCapsule capsule = KeyCapsule.builder().keyId("kid").datakeyCapsule("dc").accessPointType(2).build();
        materials.setKeyCapsule(capsule);
        assertEquals("kid", materials.getKeyCapsule().getKeyId());

        materials.setPolicyId("policy-123");
        assertEquals("policy-123", materials.getPolicyId());

        materials.setKeyPolicy("policy-content");
        assertEquals("policy-content", materials.getKeyPolicy());
    }
}
