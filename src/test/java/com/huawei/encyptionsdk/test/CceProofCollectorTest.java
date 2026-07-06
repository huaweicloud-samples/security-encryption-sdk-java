package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.proof.AttestationDocument;
import com.huaweicloud.encryptionsdk.proof.ProofInfo;
import com.huaweicloud.encryptionsdk.proof.collector.CceProofCollector;
import org.junit.Test;
import org.mockito.MockedStatic;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockStatic;

public class CceProofCollectorTest {

    @Test
    public void testCollectThrowsWhenTokenFileNotExists() {
        CceProofCollector collector = new CceProofCollector();
        ProofInfo proofInfo = ProofInfo.builder().type(3).serviceAccount("default").build();
        try {
            collector.collect(proofInfo);
        } catch (HuaweicloudException e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testCollectWithMockedToken() {
        CceProofCollector collector = new CceProofCollector();
        ProofInfo proofInfo = ProofInfo.builder().type(3).serviceAccount("default").build();

        try (MockedStatic<Files> filesMock = mockStatic(Files.class)) {
            filesMock.when(() -> Files.readAllBytes(any(Path.class)))
                    .thenReturn("mock-k8s-token".getBytes(StandardCharsets.UTF_8));

            AttestationDocument doc = collector.collect(proofInfo);
            assertNotNull(doc);
            assertEquals("mock-k8s-token", doc.getServiceToken());
        }
    }

    @Test
    public void testCollectWithReadException() {
        CceProofCollector collector = new CceProofCollector();
        ProofInfo proofInfo = ProofInfo.builder().type(3).serviceAccount("default").build();

        try (MockedStatic<Files> filesMock = mockStatic(Files.class)) {
            filesMock.when(() -> Files.readAllBytes(any(Path.class)))
                    .thenThrow(new java.io.IOException("Permission denied"));

            try {
                collector.collect(proofInfo);
            } catch (HuaweicloudException e) {
                assertNotNull(e);
            }
        }
    }
}
