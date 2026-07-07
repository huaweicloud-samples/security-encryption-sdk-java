package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.common.EcsMetadataService;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.proof.AttestationDocument;
import com.huaweicloud.encryptionsdk.proof.ProofInfo;
import com.huaweicloud.encryptionsdk.proof.collector.EcsProofCollector;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class EcsProofCollectorTest {

    @Test
    public void testCollectWithMockedSignature() {
        EcsProofCollector collector = new EcsProofCollector();
        ProofInfo proofInfo = ProofInfo.builder().type(1).build();

        try (MockedStatic<EcsMetadataService> mockStatic = Mockito.mockStatic(EcsMetadataService.class)) {
            mockStatic.when(EcsMetadataService::fetchIdentitySignature)
                    .thenReturn("mock-signature");

            AttestationDocument doc = collector.collect(proofInfo);
            assertNotNull(doc);
            assertEquals("mock-signature", doc.getEcsSignature());
        }
    }

    @Test(expected = HuaweicloudException.class)
    public void testCollectWithNullSignature() {
        EcsProofCollector collector = new EcsProofCollector();
        ProofInfo proofInfo = ProofInfo.builder().type(1).build();

        try (MockedStatic<EcsMetadataService> mockStatic = Mockito.mockStatic(EcsMetadataService.class)) {
            mockStatic.when(EcsMetadataService::fetchIdentitySignature)
                    .thenReturn(null);

            collector.collect(proofInfo);
        }
    }

    @Test(expected = HuaweicloudException.class)
    public void testCollectWithEmptySignature() {
        EcsProofCollector collector = new EcsProofCollector();
        ProofInfo proofInfo = ProofInfo.builder().type(1).build();

        try (MockedStatic<EcsMetadataService> mockStatic = Mockito.mockStatic(EcsMetadataService.class)) {
            mockStatic.when(EcsMetadataService::fetchIdentitySignature)
                    .thenReturn("");

            collector.collect(proofInfo);
        }
    }
}
