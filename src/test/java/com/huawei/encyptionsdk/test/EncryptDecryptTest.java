package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.common.FilePathForExampleConstants;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.keyrings.KmsKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import com.huaweicloud.encryptionsdk.util.CommonUtils;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * @author zc
 * @ClassName EncryptDecryptTest
 * @description:
 * @datetime 2022年 09月 16日 14:58
 */
public class EncryptDecryptTest {
    /**
     * 基础认证信息：
     * 认证用的ak和sk直接写到代码中有很大的安全风险，建议在配置文件或者环境变量中密文存放，使用时解密，确保安全；
     * 本示例以ak和sk保存在环境变量中来实现身份验证为例，运行本示例前请先在本地环境中设置环境变量HUAWEICLOUD_SDK_AK和HUAWEICLOUD_SDK_SK。
     * - ACCESS_KEY: 华为云账号Access Key
     * - SECRET_ACCESS_KEY: 华为云账号Secret Access Key, 敏感信息，建议密文存储
     */
    public static final String ACCESS_KEY = System.getenv("HUAWEICLOUD_SDK_AK");

    public static final String SECRET_ACCESS_KEY = System.getenv("HUAWEICLOUD_SDK_SK");

    public static final String PROJECT_ID = "7c55d8e5238d42e49fd9ce11b24b035b";

    public static final String REGION = "cn-north-7";

    public static final String KEYID = "aac33b45-d65e-49ea-82c3-e6f5c552dbc5";

    public static final String END_POINT = "https://kms.cn-north-7.myhuaweicloud.com";

    public static final String PROJECT_ID1 = "7c55d8e5238d42e49fd9ce11b24b035b";

    public static final String REGION1 = "cn-north-74";

    public static final String KEYID1 = "dd967cf1-f611-4371-ba74-69efec2d92a0";

    private static final String PLAIN_TEXT = "Hello World!";

    public static HuaweiConfig huaweiConfig = HuaweiConfig.builder()
        .sk(SECRET_ACCESS_KEY)
        .ak(ACCESS_KEY)
        .kmsConfigList(Collections.singletonList(new KMSConfig(REGION, KEYID, PROJECT_ID, END_POINT)))
        .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
        .isDiscovery(true)
        .build();

    @Test(expected = HuaweicloudException.class)
    public void Should_ok_When_KMSEncrypt() {
        KMSKeyring keyring = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_MULTI_REGION.getType());
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);

        Map<String, String> map = CommonUtils.getEncryptoMap();
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(
            new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        CryptoResult<byte[]> decrypt1 = huaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt1.getResult()));

        // discover 解密
        HuaweiConfig huaweiConfigDecrypt = HuaweiConfig.builder().sk(SECRET_ACCESS_KEY).ak(ACCESS_KEY).build();
        KMSKeyring keyringDecrypt = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_DISCOVERY.getType());
        HuaweiCrypto huaweiCryptoDecrypt = new HuaweiCrypto(huaweiConfigDecrypt).withKeyring(keyringDecrypt);
        CryptoResult<byte[]> decrypt = huaweiCryptoDecrypt.decrypt(result.getResult());
        System.out.println(new String(decrypt.getResult()));
        Assert.assertEquals(new String(decrypt.getResult()).intern(), PLAIN_TEXT);
    }

    @Test(expected = HuaweicloudException.class)
    public void Should_ok_When_KMSMultiKeyRingEncrypt() {
        List<KMSConfig> list = new ArrayList<>();
        list.add(new KMSConfig(REGION, KEYID, PROJECT_ID, END_POINT));
        list.add(new KMSConfig(REGION1, KEYID1, PROJECT_ID1, END_POINT));
        HuaweiConfig multiConfig = HuaweiConfig.builder()
            .sk(SECRET_ACCESS_KEY)
            .ak(ACCESS_KEY)
            .kmsConfigList(list)
            .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
            .build();
        KMSKeyring keyring = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_MULTI_REGION.getType());
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(multiConfig).withKeyring(keyring);

        Map<String, String> map = CommonUtils.getEncryptoMap();
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(
            new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        CryptoResult<byte[]> decrypt1 = huaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt1.getResult()));

        // discover 解密
        HuaweiConfig multiDecryptConfig = HuaweiConfig.builder()
            .sk(SECRET_ACCESS_KEY)
            .ak(ACCESS_KEY)
            .kmsConfigList(Collections.singletonList(new KMSConfig(REGION1, KEYID1, PROJECT_ID1)))
            .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
            .build();
        HuaweiCrypto decryptHuaweiCrypto = new HuaweiCrypto(multiDecryptConfig).withKeyring(keyring);
        CryptoResult<byte[]> decrypt = decryptHuaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt1.getResult()));

    }

    @Test
    public void Should_ok_When_RawAESEncrypt() {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
            .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_AES.getType());
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_256_FILE_PATH)));

        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);

        Map<String, String> map = CommonUtils.getEncryptoMap();
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(
            new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt.getResult()));
        // 解密
        Assert.assertEquals(new String(decrypt.getResult()), PLAIN_TEXT);
    }

    @Test
    public void Should_ok_When_RawSM4GCMEncrypt() {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
            .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_SM4_GCN.getType());
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_128_FILE_PATH)));

        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);

        Map<String, String> map = CommonUtils.getEncryptoMap();
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(
            new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt.getResult()));
        // 解密
        Assert.assertEquals(new String(decrypt.getResult()), PLAIN_TEXT);
    }

    @Test
    public void Should_ok_When_RawSM4CBCEncrypt() {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
            .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_SM4_CBC.getType());
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_128_FILE_PATH)));

        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);

        Map<String, String> map = CommonUtils.getEncryptoMap();
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(
            new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt.getResult()));
        // 解密
        Assert.assertEquals(new String(decrypt.getResult()), PLAIN_TEXT);
    }

    @Test
    public void Should_ok_When_RawSM2Encrypt() {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
            .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_SM2.getType());
        keyring.setPrivateKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.PRI_FILE_PATH)));
        keyring.setPublicKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.PUB_FILE_PATH)));

        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);

        Map<String, String> map = CommonUtils.getEncryptoMap();
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(
            new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt.getResult()));
        // 解密
        Assert.assertEquals(new String(decrypt.getResult()), PLAIN_TEXT);
    }

    @Test
    public void Should_ok_When_RawRSAEncrypt() {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.AES_128_GCM_NOPADDING)
            .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_RSA.getType());
        keyring.setPrivateKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PRI_FILE_PATH)));
        keyring.setPublicKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PUB_FILE_PATH)));

        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = CommonUtils.getEncryptoMap();
        CryptoResult<byte[]> result = huaweiCrypto.encrypt(
            new EncryptRequest(map, PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(result.getResult());
        System.out.println(new String(decrypt.getResult()));
        // 解密
        Assert.assertEquals(new String(decrypt.getResult()), PLAIN_TEXT);
    }

}
