## 加密SDK概述

```
加密 SDK（Encryption SDK）是一个客户端密码库，提供了数据、文件流加解密等功能，旨在帮助客户专注于应用程序的核心功能，而不用关心数据加密和解密的实现过程。
SDK 支持 KMS 密钥环、本地密钥环加解密等多种加解密方式，并能够支持 KMS 跨地域级的容灾。用户只需调用加解密接口即可轻松实现数据、文件流加解密。
```



## 功能特性和产品优势

- ### 极简加解密服务

数据加解密实现过程由 Encryption SDK 进行封装，用户仅需提供主密钥信息相关必要信息和调用加解密接口可实现本地海量数据加解密。

- ### 一话一密

默认情况下（未使用数据密钥缓存），Encryption SDK为它加密的每个数据对象生成唯一的数据密钥，遵循在每个加密操作中使用唯一数据密钥的加密最佳实践。

- ### 集成 KMS 托管保护密钥

Encryption SDK 集成了华为云 KMS 服务，可以指定由华为云 KMS 生成的数据加密密钥，并由主密钥加密保护。华为云 KMS 通过使用硬件安全模块 HSM（Hardware Security Module, HSM）保护密钥的安全，所有的用户主密钥（MasterKey）都由 HSM 中的根密钥保护，避免主密钥泄露，满足安全与合规要求。

- ### 支持本地主密钥加密

Encryption SDK 支持用户本地提供主密钥进行数据加解密。

- ### 支持多种加密算法

Encryption SDK 同时支持对称加密和非对称加密算法，不同填充类型，具体算法支持 AES、RSA、国密 SM2 和 SM4 等加密方式。

- ### 提供数据密钥缓存机制

Encryption SDK 具备 DEK 缓存管理功能，将 DEK 缓存在本地，用户选择使用缓存机制能够有效降低加密过程中导致的性能损耗。同时，缓存提供了最大使用次数，最大使用字节数，过期时间三个参数限定每一个数据密钥的使用，使数据密钥的不定期轮换，提高加解密的安全性。

- ### 支持多主密钥及跨地域容灾

Encryption SDK 支持同时使用多个主密钥进行数据加解密，数据加解密可指定多个 KMS 主密钥（建议指定不同region的 KMS），任意 KMS 均可解密 DEK 从而对数据进行解密，从而保证数据跨地域可用和灾备能力。



## 加密SDK接入指南

### 一、SDK获取和安装

- #### 本地安装

1.下载sdk代码，编译打包

```bash
git clone https://github.com/HuaweiCloudDeveloper/huaweicloud-encryption-sdk-java.git
cd EncryptionSDK
mvn clean install -DskipTests
```

2.项目中添加打包依赖

```markup
<dependency>
	<groupId>com.huaweicloud.sdk</groupId>
	<artifactId>huaweicloud-encryption-sdk-java</artifactId>
	<!-- 具体版本号依代码为准 -->
	<version>1.0.16</version>  
</dependency>
```

3.参照 examples 目录下的示例代码使用加密 SDK

### 二、加解密示例

```java
package com.huaweicloud.encryptionsdk.example;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.keyrings.KmsKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import com.huaweicloud.encryptionsdk.util.CommonUtils;

import org.apache.commons.lang3.Validate;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * @description: 本示例演示使用 KMS 对称主密钥，算法类型为 AES 密钥环 进行加密，然后再解密。
 * </p>
 * 你需要提供访问华为云 KMS 的 ak、sk 作为环境变量，以及可使用的 KMS 对称主密钥所属的 projectId、region、keyId 和纯文本字符串作为参数。
 */
public class KmsEncryptionExample {

    public static void main(String[] args) {
        // 1. 获取环境变量中的 ak、sk
        // 用于鉴权的AK、SK硬编码或明文存储，存在极大安全隐患。AK/SK在配置文件或环境变量中建议密文存储，在使用过程中进行解密，以保证安全。
        // 本例中，AK和SK保存在环境变量中，用于鉴权认证。在执行本示例前，需要在本地环境中设置环境变量：CLOUD_SDK_AK和CLOUD_SDK_SK。
        String ak = System.getenv("CLOUD_SDK_AK");
        String sk = System.getenv("CLOUD_SDK_SK");

        // 2. 获取参数传入的 KMS 对称主密钥所属的 projectId、region、keyId 和纯文本字符串
        String projectId = args[0];
        String region = args[1];
        String keyId = args[2];
        String plainText = args[3];

        // 3. KMS 配置基本信息：封装 region，keyId，projectId 信息（可支持多个 region，此处仅设置一个 region 信息）
        List<KMSConfig> kmsConfigList = Collections.singletonList(new KMSConfig(region, keyId, projectId));

        // 4. 初始化 KMS 相关信息及设置加密算法
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .sk(sk)
            .ak(ak)
            .kmsConfigList(kmsConfigList)
            .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
            .build();

        // 5. 选择 KMS 密钥环类型
        KMSKeyring keyring = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_MULTI_REGION.getType());

        // 6. 使用上述配置及密钥环信息初始化加密 SDK
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);

        // 7. 创建加密上下文（大多数加密数据都应该有一个关联的加密上下文来保护完整性）
        Map<String, String> map = CommonUtils.getEncryptoMap();

        // 8. 加密数据
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(
            new EncryptRequest(map, plainText.getBytes(StandardCharsets.UTF_8)));
        // 9. 解密数据
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(result.getResult());

        // 10. 验证解密后的数据是否和原始纯文本字符串一致
        Validate.isTrue(plainText.equals(new String(decrypt.getResult())));
    }
}
```
你可以在 [examples 目录](src/examples/java/com/huaweicloud/encryptionsdk/examples)查看更多示例代码。

### 三、密钥胶囊加解密示例

密钥胶囊是一种基于接入点策略的加密方式，支持 ECS、CCE 和自定义接入点类型，通过策略控制数据密钥的生成与解密权限。

```java
import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.keyrings.KmsKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.model.*;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;

import java.nio.charset.StandardCharsets;
import java.util.Collections;

public class KeyCapsuleExample {

    public static void main(String[] args) {
        // 1. 获取环境变量中的 ak、sk
        String ak = System.getenv("CLOUD_SDK_AK");
        String sk = System.getenv("CLOUD_SDK_SK");

        // 2. KMS 配置
        List<KMSConfig> kmsConfigList = Collections.singletonList(
            new KMSConfig("cn-north-7", "your_key_id", "your_project_id", "https://kms.cn-north-7.myhuaweicloud.com")
        );

        // 3. 接入点配置
        AccessPointConfig accessPointConfig = AccessPointConfig.builder()
                .type(2)  // 1:ECS, 2:Custom, 3:CCE
                .encryptedPrivateKey("your_encrypted_private_key")
                .privateKeyDecryptCallback(encryptedKey -> {
                    // 用户实现回调解密私钥，返回 Base64 格式的明文私钥
                    return "your_plain_private_key";
                })
                .build();

        // 4. 密钥胶囊配置
        KeyCapsuleConfig keyCapsuleConfig = KeyCapsuleConfig.builder()
                .region("cn-north-7")
                .defaultPolicyId("your_policy_id")
                .defaultKeyPolicy(null)  // 可选，优先使用 defaultPolicyId
                .accessPointConfig(accessPointConfig)
                .build();

        // 5. 构建加密配置
        HuaweiConfig config = HuaweiConfig.builder()
                .ak(ak)
                .sk(sk)
                .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .kmsConfigList(kmsConfigList)
                .keyCapsuleConfig(keyCapsuleConfig)
                .build();

        // 6. 创建密钥胶囊密钥环并初始化 SDK
        KMSKeyring keyring = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_KEY_CAPSULE.getType());
        HuaweiCrypto crypto = new HuaweiCrypto(config).withKeyring(keyring);

        // 7. 加密
        EncryptRequest encryptRequest = new EncryptRequest();
        encryptRequest.setPlainText("Hello, Key Capsule!".getBytes(StandardCharsets.UTF_8));
        CryptoResult<byte[]> result = crypto.encrypt(encryptRequest);

        // 8. 构建解密配置（解密无需 kmsConfigList）
        HuaweiConfig decryptConfig = HuaweiConfig.builder()
                .ak(ak)
                .sk(sk)
                .keyCapsuleConfig(keyCapsuleConfig)
                .build();
        KMSKeyring decryptKeyring = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_KEY_CAPSULE.getType());
        HuaweiCrypto decryptCrypto = new HuaweiCrypto(decryptConfig).withKeyring(decryptKeyring);

        // 9. 解密
        CryptoResult<byte[]> decryptResult = decryptCrypto.decrypt(result.getResult());
        System.out.println(new String(decryptResult.getResult(), StandardCharsets.UTF_8));
    }
}
```

### 四、密钥胶囊配置说明

#### KMSConfig（KMS 配置）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| region | String | 是 | KMS 区域，如 `cn-north-7` |
| keyId | String | 是 | KMS 对称主密钥 ID |
| projectId | String | 是 | 项目 ID |
| endpoint | String | 是 | KMS 端点，如 `https://kms.cn-north-7.myhuaweicloud.com` |

支持多个 region，加密时按顺序选择：

```java
List<KMSConfig> kmsConfigList = Arrays.asList(
    new KMSConfig("cn-north-7", "key_id_1", "project_id_1", "https://kms.cn-north-7.myhuaweicloud.com"),
    new KMSConfig("cn-south-1", "key_id_2", "project_id_2", "https://kms.cn-south-1.myhuaweicloud.com")
);
```

> **重要**：`KeyCapsuleConfig.region` 必须是 `kmsConfigList` 中已配置的 region。`KMSConfig` 支持配置多个 region，但 `KeyCapsuleConfig` 只能配置一个 region，且该 region 必须在 `kmsConfigList` 中存在。

#### AccessPointConfig（接入点配置）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| type | int | 是 | 接入点类型：1=ECS，2=Custom（通用），3=CCE |
| encryptedPrivateKey | String | 是 | 加密的私钥（Base64 编码） |
| privateKeyDecryptCallback | PrivateKeyDecryptCallback | 是 | 私钥解密回调，用户实现解密逻辑 |
| serviceAccount | String | 否 | CCE 场景的 ServiceAccount 名称（已废弃，SDK 自动从 `/var/run/secrets/kubernetes.io/serviceaccount/token` 读取 service token） |

#### KeyCapsuleConfig（密钥胶囊配置）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| region | String | 是 | 创建/解密密钥胶囊的 region |
| defaultPolicyId | String | 否 | 默认策略 ID（EncryptRequest 未指定策略时使用） |
| defaultKeyPolicy | String | 否 | 默认内联策略 JSON（优先级低于 defaultPolicyId） |
| accessPointConfig | AccessPointConfig | 是 | 接入点配置 |

#### HuaweiConfig（全局配置）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| ak | String | 是 | 华为云 Access Key |
| sk | String | 是 | 华为云 Secret Key |
| cryptoAlgorithm | CryptoAlgorithm | 是 | 加密算法（加密时必填，解密时自动从密文头解析） |
| kmsConfigList | List\<KMSConfig\> | 加密必填 | KMS 配置列表（解密时无需传入） |
| keyCapsuleConfig | KeyCapsuleConfig | 是 | 密钥胶囊配置 |
| logConfig | LogConfig | 否 | LTS 日志上报配置 |
| localLogOnly | boolean | 否 | 是否仅本地打印日志（不上报 LTS），默认 false |

#### EncryptRequest（加密请求）

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| plainText | byte[] | 是 | 待加密的明文 |
| policyId | String | 否 | 本次加密使用的策略 ID（覆盖 defaultPolicyId） |
| keyPolicy | String | 否 | 本次加密使用的内联策略 JSON（覆盖 defaultKeyPolicy） |

### 五、支持的加密算法

| 枚举值 | 说明 |
|-------|------|
| `CryptoAlgorithm.AES_128_GCM_NOPADDING` | AES-128-GCM |
| `CryptoAlgorithm.AES_256_GCM_NOPADDING` | AES-256-GCM |
| `CryptoAlgorithm.SM4_128_GCM_NOPADDING` | SM4-128-GCM |
| `CryptoAlgorithm.SM4_128_CBC_PADDING` | SM4-128-CBC-PKCS5 |

### 六、LTS 日志上报（可选）

#### 启用日志上报

```java
LogConfig logConfig = LogConfig.builder()
        .logGroupName("DSC")
        .logStreamName("crypto_operation_log")
        .region("cn-north-7")
        .projectId("your_project_id")
        .batchCountThreshold(1000)
        .lingerMs(30000)
        .batchSizeThresholdInBytes(524288)
        .ioThreadCount(4)
        .totalSizeInBytes(104857600)
        .maxBlockMs(0)
        .retries(5)
        .baseRetryBackoffMs(100)
        .maxRetryBackoffMs(500)
        .backupDir("/home/logbackup")
        .enableRecoveryOnStartup(true)
        .recoveryBatchSize(1000)
        .recoveryBatchInterval(1000)
        .build();

HuaweiConfig config = HuaweiConfig.builder()
        .ak(ak).sk(sk)
        .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
        .kmsConfigList(kmsConfigList)
        .keyCapsuleConfig(keyCapsuleConfig)
        .logConfig(logConfig)
        .build();
```

#### 仅本地打印日志（不上报 LTS）

```java
HuaweiConfig config = HuaweiConfig.builder()
        .ak(ak).sk(sk)
        .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
        .kmsConfigList(kmsConfigList)
        .keyCapsuleConfig(keyCapsuleConfig)
        .localLogOnly(true)
        .build();
```

#### LogConfig 配置说明

| 字段 | 默认值 | 说明 |
|------|-------|------|
| logGroupName | `DSC` | 日志组名称 |
| logStreamName | `crypto_operation_log` | 日志流名称 |
| region | - | LTS 服务区域（必填） |
| projectId | - | 项目 ID（必填） |
| batchCountThreshold | 1000 | 缓冲区记录条数阈值 |
| lingerMs | 30000 | 异步上报间隔（毫秒） |
| batchSizeThresholdInBytes | 524288 | 批量大小阈值（字节） |
| ioThreadCount | CPU 核数 | IO 线程数 |
| totalSizeInBytes | 104857600 | 缓冲区大小上限（100MB） |
| maxBlockMs | 0 | 发送阻塞时间（毫秒），0=不阻塞 |
| retries | 5 | 重试次数 |
| baseRetryBackoffMs | 100 | 首次重试退避时间（毫秒） |
| maxRetryBackoffMs | 500 | 最大重试退避时间（毫秒） |
| backupDir | `~/lts_log_backup` | 失败日志备份目录 |
| enableRecoveryOnStartup | true | 启动时恢复失败日志 |
| recoveryBatchSize | 1000 | 恢复批量大小 |
| recoveryBatchInterval | 1000 | 恢复批次间隔（毫秒） |

### 七、缓存（可选）

```java
LocalDataKeyCache localDataKeyCache = new LocalDataKeyCache();
localDataKeyCache.setCapacity(10);

CacheCryptoMeterialManager cacheManager = new CacheCryptoMeterialManager(localDataKeyCache, config);
cacheManager.setMaxByteLimit(3000);
cacheManager.setMaxMessageLimit(1000);
cacheManager.setSurvivalTime(5000);

crypto.withCryptoMeterialManager(cacheManager);
```

| 配置项 | 默认值 | 说明 |
|-------|-------|------|
| capacity | - | 最大缓存容量，超出按 LRU 淘汰 |
| maxByteLimit | Long.MAX_VALUE | 单个数据密钥加密 byte 最大数量 |
| maxMessageLimit | Integer.MAX_VALUE | 单个数据密钥加密数据条数最大限制 |
| survivalTime | 1000000 | 缓存存活时间（毫秒） |

### 八、安全建议

- AK/SK 不应硬编码在代码中，建议从环境变量或密钥管理服务获取
- `privateKeyDecryptCallback` 中应实现安全的私钥解密逻辑，避免明文存储私钥