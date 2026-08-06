package com.huaweicloud.encryptionsdk.examples;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.keyrings.KmsKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
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
