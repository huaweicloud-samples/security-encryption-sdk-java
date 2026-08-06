package com.huawei.pca;

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
import org.apache.commons.codec.DecoderException;
import org.apache.commons.lang3.Validate;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * @description: 本示例演示使用 KMSDiscoveryKeyring 密钥环进行加密，然后解密。
 * </p>
 * 使用 KMSDiscoveryKeyring 密钥环进行解密无需再传递 keyId，regionId，projectId 等信息，仅需ak，sk即可。
 * </p>
 * 你需要提供访问华为云 KMS 的 ak、sk 作为环境变量，以及可使用的 KMS 对称主密钥所属的 projectId、region、keyId 和纯文本字符串作为参数。
 */
public class KmsDiscoveryEncryptionExample {

    public static void main(String[] args) throws IOException, DecoderException, NoSuchAlgorithmException {
        // 1. 获取环境变量中的 ak、sk
        // 用于鉴权的AK、SK硬编码或明文存储，存在极大安全隐患。AK/SK在配置文件或环境变量中建议密文存储，在使用过程中进行解密，以保证安全。
        // 本例中，AK和SK保存在环境变量中，用于鉴权认证。在执行本示例前，需要在本地环境中设置环境变量：CLOUD_SDK_AK和CLOUD_SDK_SK。
        String ak = "HPUAUV4D8QNT9CVENDM6";
        String sk = "UAr5KV317Vq1sxASOfzrHhmnV3eFj1gseba5JAxa";

        // 2. 获取参数传入的 KMS 对称主密钥所属的 projectId、region、keyId 和纯文本字符串
        String projectId = "d4e559b49b3b403da5279723299ed4a6";
        String region = "cn-north-7";
        String keyId = "cc05882f-6e26-4b57-a450-dc5020acf4f4";
        String endpoint = "https://kms.cn-north-7.myhuaweicloud.com";

        String originFilePath = "D:\\temp\\0804\\sdk\\new_test.bin";
        String encryptFilePath = "D:\\temp\\0804\\sdk\\enc\\new_test_enc_0806.bin";
        String decryptFilePath = "D:\\temp\\0804\\sdk\\dec\\new_test_dec_0806.bin";

        // 3. KMS 配置基本信息：封装 region，keyId，projectId 信息（可支持多个 region，此处仅设置一个 region 信息）
        List<KMSConfig> kmsConfigList = Collections.singletonList(new KMSConfig(region, keyId, projectId, endpoint));

        // 4. 初始化 KMS 相关信息及设置加密算法（注意需要开启 discover）
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .sk(sk)
            .ak(ak)
            .kmsConfigList(kmsConfigList)
            .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
            // 开启discover密钥环
            .isDiscovery(true)
            .build();

        // 5. 选择 KMS 密钥环类型
        KMSKeyring keyring = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_MULTI_REGION.getType());

        // 6. 使用上述配置及密钥环信息初始化加密 SDK
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);

        // 7. 创建加密上下文（大多数加密数据都应该有一个关联的加密上下文来保护完整性）
        Map<String, String> map = CommonUtils.getEncryptoMap();

        // 8. 加密数据
        huaweiCrypto.encrypt(originFilePath, encryptFilePath, null);

        System.out.println("文件加密完成");

        // 9. 构建 KMS discovery 解密 SDK（无需再传递 keyId，regionId，projectId 等信息）
        HuaweiConfig huaweiConfigDiscovery = HuaweiConfig.builder().sk(sk).ak(ak).build();
        KMSKeyring keyringDiscovery = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_DISCOVERY.getType());
        HuaweiCrypto huaweiCryptoDecrypt = new HuaweiCrypto(huaweiConfigDiscovery).withKeyring(keyringDiscovery);

        // 10. 解密数据
        huaweiCryptoDecrypt.decrypt(encryptFilePath, decryptFilePath);

        System.out.println("文件解密完成");
    }
}
