package com.huaweicloud.encryptionsdk.examples;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.cache.LocalDataKeyCache;
import com.huaweicloud.encryptionsdk.keyrings.KmsKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.log.LogConfig;
import com.huaweicloud.encryptionsdk.meterialmanager.CacheCryptoMeterialManager;
import com.huaweicloud.encryptionsdk.model.*;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import org.apache.commons.lang3.Validate;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * 密钥胶囊加密示例
 */
public class KeyCapsuleEncryptionExample {

    public static void main(String[] args) throws Exception {
        // 1. 获取环境变量中的 ak、sk
        // 用于鉴权的AK、SK硬编码或明文存储，存在极大安全隐患。AK/SK在配置文件或环境变量中建议密文存储，在使用过程中进行解密，以保证安全。
        // 本例中，AK和SK保存在环境变量中，用于鉴权认证。在执行本示例前，需要在本地环境中设置环境变量：CLOUD_SDK_AK和CLOUD_SDK_SK。
        String ak = System.getenv("CLOUD_SDK_AK");
        String sk = System.getenv("CLOUD_SDK_SK");

        // 2. 获取参数传入的 KMS 对称主密钥所属的 projectId、region、keyId 和纯文本字符串
        String projectId = "project_id";
        String region = "cn-north-4";
        String keyId = "kms_key_id";
        String endpoint = "https://kms.cn-north-4.myhuaweicloud.com";

        // 3. KMS 配置基本信息：封装 region，keyId，projectId 信息（可支持多个 region，此处仅设置一个 region 信息）
        List<KMSConfig> kmsConfigList = Collections.singletonList(new KMSConfig(region, keyId, projectId, endpoint));

        // 4. 密钥胶囊配置
        // 创建或解密密钥胶囊region，须为kmsConfigList中的某一region
        String keyCapsuleRegion = "cn-north-4";
        // 默认密钥策略ID和默认内联策略，优先使用默认内联策略
        String defaultPolicyId = "your_default_policy_id";
        // 内联策略参考："{ \"version\": \"v1.0\", \"allowed_access_point\": [\"068fc3a1-4769-4f4f-805a-ae204dc5e251\"], \"validity_period\": {\"start_time\": \"2026-06-01T20:00:49Z\", \"end_time\": \"2026-07-25T20:00:49Z\"} }"
        String defaultKeyPolicy = "your_default_key_policy";
        // 接入点类型 1 - ECS, 2 - 通用场景, 3 - CCE
        int accessPointType = 2;
        // 加密的私钥
        String privateKey = "your_encrypted_private_key";

        // 构建接入点配置
        AccessPointConfig accessPointConfig = AccessPointConfig.builder()
                .type(accessPointType)  // 使用密钥对类型的证明收集器
                .encryptedPrivateKey(privateKey)
                .privateKeyDecryptCallback(encryptedKey -> {
                    // 用户实现回调方法解密私钥，encryptedKey是密文，用户需要返回Base64格式的明文私钥
                    // 明文密钥参考："MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgI6G5tkwYjAcmAH9cPFGaEQKNVxP2v0hFtRuHMT+KgIagCgYIKoZIzj0DAQehRANCAARcE5/Wz7zM8ABRha9vAvfAJS//v2hxfSxS67F+6xRoVLOzEF+lURfD......"
                    String plainPrivateKey = "your_plain_private_key";
                    return plainPrivateKey;
                })
                .build();

        // 构建密钥胶囊配置
        KeyCapsuleConfig keyCapsuleConfig = KeyCapsuleConfig.builder()
                .region(keyCapsuleRegion)
                .defaultPolicyId(defaultPolicyId)
                .defaultKeyPolicy(defaultKeyPolicy)
                .accessPointConfig(accessPointConfig)
                .build();

        // 5. 上报LTS日志配置（可选）
        // 上报日志region
        String logRegion = "cn-north-4";
        String logProjectId = "your_log_project_id";
        // 1.“日志组ID”和“日志流ID”不为空时，优先使用ID上报日志; 2.ID为空，则使用“日志组名称”和“日志流名称”上报日志
        // 日志组ID（可选）
        String logGroupId = "your_log_group_id";
        // 日志流ID（可选）
        String logStreamId = "your_log_stream_id";
        // 日志组名称，默认为"DSC"
        String logGroupName = "DSC";
        // 日志流名称，默认为"crypto_operation_log"
        String logStreamName = "crypto_operation_log";
        // 失败日志备份目录，SDK会在下次启动时读取失败的日志文件并尝试重新上报
        String backupDir = "/home/logbackup";

        // 构建LTS日志配置
        LogConfig logConfig = LogConfig.builder()
                .logGroupId(logGroupId)           // 日志组ID
                .logStreamId(logStreamId)           // 日志流ID
                .logGroupName(logGroupName)           // 日志组名称
                .logStreamName(logStreamName)           // 日志流名称
                .region(logRegion)                       // LTS服务区域
                .projectId(logProjectId)                // 项目ID

                // 特性要求配置（可选）
                .batchCountThreshold(1000)            // 缓冲区默认1000条记录
                .lingerMs(30000)                       // 异步任务每30秒执行一次
                .batchSizeThresholdInBytes(524288)    // 0.5MB

                // 性能配置（可选）
                .ioThreadCount(4)                      // 4个IO线程
                .totalSizeInBytes(104857600)          // 100MB缓冲区
                .maxBlockMs(0)                        // 不阻塞

                // 重试配置（可选）
                .retries(5)                           // 5次重试
                .baseRetryBackoffMs(100)              // 100ms首次退避
                .maxRetryBackoffMs(500)               // 500ms最大退避

                // 失败日志备份配置
                .backupDir(backupDir)                // 失败日志备份目录
                .enableRecoveryOnStartup(true)       // 启动时恢复失败的日志
                .recoveryBatchSize(1000)             // 恢复时的批量大小
                .recoveryBatchInterval(1000)         // 恢复批次间隔时间（毫秒）
                .build();

        // 6. 构建全局配置（包含LTS日志配置）
        HuaweiConfig config = HuaweiConfig.builder()
                .ak(ak)
                .sk(sk)
                // 密钥算法
                .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                // KMS配置
                .kmsConfigList(kmsConfigList)
                // 密钥胶囊配置
                .keyCapsuleConfig(keyCapsuleConfig)
                // 日志配置
                .logConfig(logConfig)
                .build();

        // 7. 创建密钥胶囊密钥环
        KMSKeyring keyring = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_KEY_CAPSULE.getType());

        // 8. 使用上述配置及密钥环信息初始化加密 SDK
        HuaweiCrypto crypto = new HuaweiCrypto(config).withKeyring(keyring);

        // 9. 创建本地数据密钥缓存对象（可选）
        LocalDataKeyCache localDataKeyCache = new LocalDataKeyCache();
        // 设置数据密钥最大缓存容量，超出容量则按照LUR规则进行删除
        localDataKeyCache.setCapacity(10);
        // 初始化数据密钥缓存管理器
        CacheCryptoMeterialManager cacheCryptoMeterialManager = new CacheCryptoMeterialManager(localDataKeyCache, config);
        // 单个被缓存的数据密钥加密byte最大数量限制，默认为Long.MAX_VALUE
        cacheCryptoMeterialManager.setMaxByteLimit(3000);
        // 单个被缓存的数据密钥加密数据条数最大限制,默认为Integer.MAX_VALUE
        cacheCryptoMeterialManager.setMaxMessageLimit(1000);
        // 数据密钥缓存存活时间，单位为ms，默认为1000s
        cacheCryptoMeterialManager.setSurvivalTime(5000);
        crypto.withCryptoMeterialManager(cacheCryptoMeterialManager);

        // 10. 加密数据
        EncryptRequest encryptRequest = new EncryptRequest();
        // 如果不想使用默认的密钥策略ID和默认内联密钥，用户可以通过EncryptRequest传入本次创建密钥胶囊使用的策略ID或内联策略
        String customPolicyId = "your_policy_id";
        String customKeyPolicy = "your_key_policy";
        encryptRequest.setPolicyId(customPolicyId);
        encryptRequest.setKeyPolicy(customKeyPolicy);
        String plainText = "Hello, Key Capsule!";
        encryptRequest.setPlainText(plainText.getBytes(StandardCharsets.UTF_8));
        // 执行加密
        CryptoResult<byte[]> result = crypto.encrypt(encryptRequest);

        // 11. 构建 KMS keyCapsule 解密 SDK（无需再传递 kmsConfigList 等信息）
        HuaweiConfig huaweiConfigDecrypt = HuaweiConfig.builder()
                .ak(ak)
                .sk(sk)
                // 密钥胶囊配置
                .keyCapsuleConfig(keyCapsuleConfig)
                // 日志配置
                .logConfig(logConfig)
                .build();
        KMSKeyring keyCapsuleKeyring = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_KEY_CAPSULE.getType());
        HuaweiCrypto huaweiCryptoDecrypt = new HuaweiCrypto(huaweiConfigDecrypt).withKeyring(keyCapsuleKeyring);

        // 12. 解密数据
        CryptoResult<byte[]> decrypt = huaweiCryptoDecrypt.decrypt(result.getResult());

        // 13. 验证解密后的数据是否和原始纯文本字符串一致
        Validate.isTrue(Arrays.equals(plainText.getBytes(StandardCharsets.UTF_8), decrypt.getResult()));
    }
}