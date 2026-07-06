package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.exception.KeyringNotFoundException;
import com.huaweicloud.encryptionsdk.keyrings.KmsKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSDiscoveryKeyring;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyCapsuleKeyring;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSMultiRegionKeyring;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class KmsKeyringFactoryTest {

    @Test
    public void testGetKmsDiscoveryKeyring() {
        KmsKeyringFactory factory = new KmsKeyringFactory();
        Object keyring = factory.getKeyring("discovery");
        assertNotNull(keyring);
        assertTrue(keyring instanceof KMSDiscoveryKeyring);
    }

    @Test
    public void testGetKmsMultiRegionKeyring() {
        KmsKeyringFactory factory = new KmsKeyringFactory();
        Object keyring = factory.getKeyring("multi");
        assertNotNull(keyring);
        assertTrue(keyring instanceof KMSMultiRegionKeyring);
    }

    @Test
    public void testGetKmsKeyCapsuleKeyring() {
        KmsKeyringFactory factory = new KmsKeyringFactory();
        Object keyring = factory.getKeyring("key_capsule");
        assertNotNull(keyring);
        assertTrue(keyring instanceof KMSKeyCapsuleKeyring);
    }

    @Test(expected = KeyringNotFoundException.class)
    public void testGetUnsupportedType() {
        KmsKeyringFactory factory = new KmsKeyringFactory();
        factory.getKeyring("UNKNOWN_TYPE");
    }
}
