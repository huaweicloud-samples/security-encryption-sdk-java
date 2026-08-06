package com.huaweicloud.encryptionsdk;

import com.huaweicloud.encryptionsdk.cache.LocalDataKeyCache;
import com.huaweicloud.encryptionsdk.keyrings.KmsKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.log.LogConfig;
import com.huaweicloud.encryptionsdk.meterialmanager.CacheCryptoMeterialManager;
import com.huaweicloud.encryptionsdk.model.AccessPointConfig;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.KeyCapsuleConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Validate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

public class KeyCapsuleEncryptionExample {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(KeyCapsuleEncryptionExample.class);

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java -jar encryption-sdk.jar <config.properties>");
            System.exit(1);
        }

        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(args[0])) {
            props.load(fis);
        }

        String ak = props.getProperty("ak");
        String sk = props.getProperty("sk");
        String securityToken = props.getProperty("securityToken");

        String projectId = props.getProperty("kms.projectId");
        String region = props.getProperty("kms.region");
        String keyId = props.getProperty("kms.keyId");
        String endpoint = props.getProperty("kms.endpoint");
        List<KMSConfig> kmsConfigList = Collections.singletonList(new KMSConfig(region, keyId, projectId, endpoint));

        String keyCapsuleRegion = props.getProperty("keyCapsule.region");
        String defaultPolicyId = props.getProperty("keyCapsule.defaultPolicyId");
        String defaultKeyPolicy = props.getProperty("keyCapsule.defaultKeyPolicy");
        int accessPointType = Integer.parseInt(props.getProperty("keyCapsule.accessPointType"));
        String encryptedPrivateKey = props.getProperty("keyCapsule.encryptedPrivateKey");
        String plainPrivateKey = props.getProperty("keyCapsule.plainPrivateKey");

        AccessPointConfig accessPointConfig = AccessPointConfig.builder()
                .type(accessPointType)
                .encryptedPrivateKey(encryptedPrivateKey)
                .privateKeyDecryptCallback(encryptedKey -> plainPrivateKey)
                .serviceAccount(props.getProperty("keyCapsule.serviceAccount"))
                .build();

        KeyCapsuleConfig keyCapsuleConfig = KeyCapsuleConfig.builder()
                .region(keyCapsuleRegion)
                .defaultPolicyId(defaultPolicyId)
                .defaultKeyPolicy(defaultKeyPolicy)
                .accessPointConfig(accessPointConfig)
                .build();

        boolean logEnabled = Boolean.parseBoolean(props.getProperty("log.enabled", "false"));
        LogConfig logConfig = null;
        HuaweiConfig config = null;
        if (logEnabled) {
            logConfig = LogConfig.builder()
                    .logGroupName(props.getProperty("log.groupName"))
                    .logStreamName(props.getProperty("log.streamName"))
                    .region(props.getProperty("log.region"))
                    .projectId(props.getProperty("log.projectId"))
                    .batchCountThreshold(Integer.parseInt(props.getProperty("log.batchCountThreshold", "1000")))
                    .lingerMs(Integer.parseInt(props.getProperty("log.lingerMs", "30000")))
                    .batchSizeThresholdInBytes(Integer.parseInt(props.getProperty("log.batchSizeThresholdInBytes", "524288")))
                    .ioThreadCount(Integer.parseInt(props.getProperty("log.ioThreadCount", "4")))
                    .totalSizeInBytes(Integer.parseInt(props.getProperty("log.totalSizeInBytes", "104857600")))
                    .maxBlockMs(Integer.parseInt(props.getProperty("log.maxBlockMs", "0")))
                    .retries(Integer.parseInt(props.getProperty("log.retries", "5")))
                    .baseRetryBackoffMs(Integer.parseInt(props.getProperty("log.baseRetryBackoffMs", "100")))
                    .maxRetryBackoffMs(Integer.parseInt(props.getProperty("log.maxRetryBackoffMs", "500")))
                    .backupDir(props.getProperty("log.backupDir", "/home/logbackup"))
                    .enableRecoveryOnStartup(Boolean.parseBoolean(props.getProperty("log.enableRecoveryOnStartup", "true")))
                    .recoveryBatchSize(Integer.parseInt(props.getProperty("log.recoveryBatchSize", "1000")))
                    .recoveryBatchInterval(Integer.parseInt(props.getProperty("log.recoveryBatchInterval", "1000")))
                    .build();
            config = HuaweiConfig.builder()
                    .ak(ak)
                    .sk(sk)
                    .securityToken(securityToken)
                    .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                    .kmsConfigList(kmsConfigList)
                    .keyCapsuleConfig(keyCapsuleConfig)
                    .logConfig(logConfig)
                    .build();
        } else {
            config = HuaweiConfig.builder()
                    .ak(ak)
                    .sk(sk)
                    .securityToken(securityToken)
                    .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                    .kmsConfigList(kmsConfigList)
                    .keyCapsuleConfig(keyCapsuleConfig)
                    .build();
        }

         

        KMSKeyring keyring = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_KEY_CAPSULE.getType());
        HuaweiCrypto crypto = new HuaweiCrypto(config).withKeyring(keyring);

        boolean cacheEnabled = Boolean.parseBoolean(props.getProperty("cache.enabled", "false"));
        if (cacheEnabled) {
            LocalDataKeyCache localDataKeyCache = new LocalDataKeyCache();
            localDataKeyCache.setCapacity(Integer.parseInt(props.getProperty("cache.capacity", "10")));
            CacheCryptoMeterialManager cacheCryptoMeterialManager = new CacheCryptoMeterialManager(localDataKeyCache, config);
            cacheCryptoMeterialManager.setMaxByteLimit(Long.parseLong(props.getProperty("cache.maxByteLimit", "3000")));
            cacheCryptoMeterialManager.setMaxMessageLimit(Integer.parseInt(props.getProperty("cache.maxMessageLimit", "1000")));
            cacheCryptoMeterialManager.setSurvivalTime(Long.parseLong(props.getProperty("cache.survivalTime", "5000")));
            crypto.withCryptoMeterialManager(cacheCryptoMeterialManager);
        }

        EncryptRequest encryptRequest = new EncryptRequest();
        String customPolicyId = props.getProperty("test.encrypt.policyId");
        String customKeyPolicy = props.getProperty("test.encrypt.keyPolicy");
        if (StringUtils.isNotEmpty(customPolicyId)) {
            encryptRequest.setPolicyId(customPolicyId);
        }
        if (StringUtils.isNotEmpty(customKeyPolicy)) {
            encryptRequest.setKeyPolicy(customKeyPolicy);
        }
        boolean testFileEnabled = Boolean.parseBoolean(props.getProperty("test.file.enabled", "false"));
        if (testFileEnabled) {
            String originFilePath = props.getProperty("test.file.path.origin");
            String encryptFilePath = props.getProperty("test.file.path.encrypt");
            String decryptFilePath = props.getProperty("test.file.path.decrypt");
            crypto.encrypt(originFilePath, encryptFilePath, null);
            LOGGER.info("加密成功，源文件：{}, 加密后文件：{}", originFilePath, encryptFilePath);
            crypto.decrypt(encryptFilePath, decryptFilePath);
            LOGGER.info("解密成功：源文件：{}， 解密后文件：{}", encryptFilePath, decryptFilePath);
            crypto.getLogReporterManager().shutdown();
        } else {
            String plainText = props.getProperty("test.plainTex", "Hello, Key Capsule!");
            encryptRequest.setPlainText(plainText.getBytes(StandardCharsets.UTF_8));
            LOGGER.info("原文: {}, HEX: {}", plainText, bytesToHex(plainText.getBytes(StandardCharsets.UTF_8)));
            CryptoResult<byte[]> result = crypto.encrypt(encryptRequest);
            LOGGER.info("加密成功，密文HEX: {}", bytesToHex(result.getResult()));

            HuaweiConfig huaweiConfigDecrypt = null;
            if (logConfig == null) {
                huaweiConfigDecrypt = HuaweiConfig.builder()
                        .ak(ak)
                        .sk(sk)
                        .securityToken(securityToken)
                        .keyCapsuleConfig(keyCapsuleConfig)
                        .build();
            } else {
                huaweiConfigDecrypt = HuaweiConfig.builder()
                        .ak(ak)
                        .sk(sk)
                        .securityToken(securityToken)
                        .keyCapsuleConfig(keyCapsuleConfig)
                        .logConfig(logConfig)
                        .build();
            }
            
            KMSKeyring keyCapsuleKeyring = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_KEY_CAPSULE.getType());
            HuaweiCrypto huaweiCryptoDecrypt = new HuaweiCrypto(huaweiConfigDecrypt).withKeyring(keyCapsuleKeyring);

            CryptoResult<byte[]> decrypt = huaweiCryptoDecrypt.decrypt(result.getResult());
            LOGGER.info("解密成功: {}, HEX: {}", new String(decrypt.getResult()), bytesToHex(decrypt.getResult()));

            Validate.isTrue(Arrays.equals(plainText.getBytes(StandardCharsets.UTF_8), decrypt.getResult()));
            crypto.getLogReporterManager().shutdown();
            huaweiCryptoDecrypt.getLogReporterManager().shutdown();
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
