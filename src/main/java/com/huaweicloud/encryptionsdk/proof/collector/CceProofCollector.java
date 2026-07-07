package com.huaweicloud.encryptionsdk.proof.collector;

import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.proof.AttestationDocument;
import com.huaweicloud.encryptionsdk.proof.ProofCollector;
import com.huaweicloud.encryptionsdk.proof.ProofInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class CceProofCollector implements ProofCollector {

    private static final Logger LOGGER = LoggerFactory.getLogger(CceProofCollector.class);

    private static final String SERVICE_ACCOUNT_TOKEN_PATH =
        "/var/run/secrets/kubernetes.io/serviceaccount/token";

    @Override
    public AttestationDocument collect(ProofInfo proofInfo) {
        String serviceToken = readServiceAccountToken();
        LOGGER.info("CCE service token obtained from {}", SERVICE_ACCOUNT_TOKEN_PATH);
        return AttestationDocument.builder()
                .serviceToken(serviceToken)
                .build();
    }

    private String readServiceAccountToken() {
        try {
            return new String(Files.readAllBytes(Paths.get(SERVICE_ACCOUNT_TOKEN_PATH)), StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.COLLECT_PROOF_EXCEPTION.getMessage(), e);
        }
    }
}
