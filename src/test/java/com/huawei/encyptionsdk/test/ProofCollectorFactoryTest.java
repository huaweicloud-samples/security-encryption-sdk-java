package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.proof.AttestationDocument;
import com.huaweicloud.encryptionsdk.proof.ProofCollectorFactory;
import com.huaweicloud.encryptionsdk.proof.ProofCollector;
import com.huaweicloud.encryptionsdk.proof.collector.CceProofCollector;
import com.huaweicloud.encryptionsdk.proof.collector.EcsProofCollector;
import com.huaweicloud.encryptionsdk.proof.collector.KeyPairProofCollector;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ProofCollectorFactoryTest {

    @Test
    public void testGetCollectorEcs() {
        ProofCollector collector = ProofCollectorFactory.getCollector(1);
        assertNotNull(collector);
        assertTrue(collector instanceof EcsProofCollector);
    }

    @Test
    public void testGetCollectorKeyPair() {
        ProofCollector collector = ProofCollectorFactory.getCollector(2);
        assertNotNull(collector);
        assertTrue(collector instanceof KeyPairProofCollector);
    }

    @Test
    public void testGetCollectorCce() {
        ProofCollector collector = ProofCollectorFactory.getCollector(3);
        assertNotNull(collector);
        assertTrue(collector instanceof CceProofCollector);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetCollectorNullType() {
        ProofCollectorFactory.getCollector(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetCollectorUnsupportedType() {
        ProofCollectorFactory.getCollector(99);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testRegisterCollectorNull() {
        ProofCollectorFactory.registerCollector(100, null);
    }

    @Test
    public void testRegisterCustomCollector() {
        ProofCollector custom = proofInfo -> AttestationDocument.builder().ecsSignature("custom").build();
        ProofCollectorFactory.registerCollector(100, custom);
        ProofCollector retrieved = ProofCollectorFactory.getCollector(100);
        assertNotNull(retrieved);
        AttestationDocument doc = retrieved.collect(null);
        assertTrue(doc.toString().contains("custom"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCollectNullProofInfo() {
        ProofCollectorFactory.collect(null);
    }
}
