package com.huaweicloud.encryptionsdk.examples;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import com.huaweicloud.encryptionsdk.util.CommonUtils;

import org.apache.commons.lang3.Validate;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Map;

/**
 * @description: 本示例演示使用本地对称主密钥，算法类型为 AES 密钥环 进行加密，然后再解密。
 * </p>
 * 你需要提供 KMS 对称秘钥和纯文本字符串作为参数。
 */
public class LocalAesKeyringEncryptionExample {

    public static void main(String[] args) {
        // 1. 获取参数传入的对称密钥以及需要纯文本字符串
        String symemetryKey = args[0];
        String plainText = args[1];

        // 2. 初始化加解密相关配置及加密算法
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.AES_128_GCM_NOPADDING)
            .build();

        // 3. 选择本地密钥环类型 AES
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_AES.getType());

        // 4. 设置 AES 密钥环使用的对称主密钥
        ArrayList<byte[]> bytes = new ArrayList<>();
        bytes.add(Base64.getDecoder().decode(symemetryKey.getBytes(StandardCharsets.UTF_8)));
        keyring.setSymmetricKey(bytes);

        // 5. 使用上述配置及密钥环信息初始化加密 SDK
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);

        // 6. 创建加密上下文（大多数加密数据都应该有一个关联的加密上下文来保护完整性）
        Map<String, String> map = CommonUtils.getEncryptoMap();

        // 7. 加密数据
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(
            new EncryptRequest(map, plainText.getBytes(StandardCharsets.UTF_8)));

        // 8. 解密数据
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(result.getResult());

        // 9. 验证解密后的数据是否和原始纯文本字符串一致
        Validate.isTrue(plainText.equals(new String(decrypt.getResult())));
    }
}
