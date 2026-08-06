package com.huaweicloud.encryptionsdk.examples;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.cache.LocalDataKeyCache;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.meterialmanager.CacheCryptoMeterialManager;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import com.huaweicloud.encryptionsdk.util.CommonUtils;

import org.apache.commons.lang3.Validate;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * @description: 本示例演示基于密钥缓存的加密/解密示例，缓存同时支持 KMS 和本地主密钥。
 * </p>
 * 你需要提供 KMS 非对称秘钥和纯文本字符串作为参数。
 */
public class CacheEncryptionExample {

    public static void main(String[] args) {
        // 1. 获取参数传入的非对称密钥以及需要纯文本字符串
        // 编码后的公钥
        String rsaPublicKey = args[0];
        // 编码后的私钥
        String rsaPrivateKey = args[1];
        String plainText = args[2];

        // 2. 初始化加解密相关配置及加密算法
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
            .build();

        // 3. 选择本地密钥环类型 AES
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_RSA.getType());

        // 4. 设置 RSA 密钥环使用的非对称主密钥
        // 设置RSA密钥环加密使用的公钥
        byte[] rsapub = Base64.getDecoder().decode(rsaPublicKey);
        keyring.setPublicKey(rsapub);
        // 设置RSA密钥环加密使用的私钥
        byte[] rsaPri = Base64.getDecoder().decode(rsaPrivateKey);
        keyring.setPrivateKey(rsaPri);

        // 5. 使用上述配置及密钥环信息初始化加密 SDK
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);

        // 6. 创建本地数据密钥缓存对象
        LocalDataKeyCache localDataKeyCache = new LocalDataKeyCache();
        // 设置数据密钥最大缓存容量，超出容量则按照LUR规则进行删除
        localDataKeyCache.setCapacity(10);

        // 7. 初始化数据密钥缓存管理器
        CacheCryptoMeterialManager cacheCryptoMeterialManager = new CacheCryptoMeterialManager(localDataKeyCache,
            huaweiConfig);
        // 单个被缓存的数据密钥加密byte最大数量限制，默认为Long.MAX_VALUE
        cacheCryptoMeterialManager.setMaxByteLimit(50);
        // 单个被缓存的数据密钥加密数据条数最大限制,默认为Integer.MAX_VALUE
        cacheCryptoMeterialManager.setMaxMessageLimit(1000);
        // 数据密钥缓存存活时间，单位为ms，默认为1000s
        cacheCryptoMeterialManager.setSurvivalTime(5000);
        huaweiCrypto.withCryptoMeterialManager(cacheCryptoMeterialManager);

        // 8. 创建加密上下文（大多数加密数据都应该有一个关联的加密上下文来保护完整性）
        Map<String, String> map = CommonUtils.getEncryptoMap();

        // 9. 加密数据
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(
            new EncryptRequest(map, plainText.getBytes(StandardCharsets.UTF_8)));

        // 10. 解密数据
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(result.getResult());

        // 11. 验证解密后的数据是否和原始纯文本字符串一致
        Validate.isTrue(plainText.equals(new String(decrypt.getResult()).intern()));
    }
}
