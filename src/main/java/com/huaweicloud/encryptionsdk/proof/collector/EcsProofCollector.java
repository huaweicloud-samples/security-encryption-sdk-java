package com.huaweicloud.encryptionsdk.proof.collector;

import com.huaweicloud.encryptionsdk.common.EcsMetadataService;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.proof.AttestationDocument;
import com.huaweicloud.encryptionsdk.proof.ProofCollector;
import com.huaweicloud.encryptionsdk.proof.ProofInfo;

public class EcsProofCollector implements ProofCollector {

    @Override
    public AttestationDocument collect(ProofInfo proofInfo) {
        String signature = EcsMetadataService.fetchIdentitySignature();
        if (signature == null || signature.isEmpty()) {
            throw new HuaweicloudException(ErrorMessage.COLLECT_PROOF_EXCEPTION.getMessage());
        }
        return AttestationDocument.builder()
            .ecsSignature(signature)
            .build();
    }
}