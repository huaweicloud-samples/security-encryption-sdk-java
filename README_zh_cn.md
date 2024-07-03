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