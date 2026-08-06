package com.huawei.encyptionsdk.test.cache;

import com.huawei.encyptionsdk.test.EncryptDecryptTest;
import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.cache.LocalDataKeyCache;
import com.huaweicloud.encryptionsdk.common.FilePathForExampleConstants;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.keyrings.KmsKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.meterialmanager.CacheCryptoMeterialManager;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import com.huaweicloud.encryptionsdk.util.CommonUtils;
import org.junit.Before;
import org.junit.Test;

import java.io.FileNotFoundException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertSame;

public class CachingDataKeyTest {

    private HuaweiCrypto huaweiCrypto;

    private HuaweiConfig config;

    private static final String PLAIN_TEXT = "Hello World!";

    private static final Charset ENCODING = StandardCharsets.UTF_8;

    @Before
    public void setUp() throws FileNotFoundException {
        config = HuaweiConfig.builder().cryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING).build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_RSA.getType());
        keyring.setPrivateKey(
            Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PRI_FILE_PATH)));
        keyring.setPublicKey(
            Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PUB_FILE_PATH)));
        huaweiCrypto = new HuaweiCrypto(config).withKeyring(keyring);
    }

    @Test
    public void Should_ok_When_CacheTest() throws InterruptedException {
        Map<String, String> encryptionContext = CommonUtils.getEncryptionContext();

        CacheCryptoMeterialManager cacheCryptoMeterialManager = new CacheCryptoMeterialManager(new LocalDataKeyCache(),
            config);
        cacheCryptoMeterialManager.setMaxByteLimit(50);
        cacheCryptoMeterialManager.setSurvivalTime(5000);
        huaweiCrypto.withCryptoMeterialManager(cacheCryptoMeterialManager);

        CryptoResult<byte[]> encryptResult = huaweiCrypto.encrypt(
            new EncryptRequest(encryptionContext, PLAIN_TEXT.getBytes(ENCODING)));
        byte[] cipherResult = encryptResult.getResult();

        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(cipherResult);
        assertSame(new String(decrypt.getResult()).intern(), PLAIN_TEXT);

        Thread.sleep(2000);
        encryptResult = huaweiCrypto.encrypt(new EncryptRequest(encryptionContext, "cache".getBytes(ENCODING)));
        cipherResult = encryptResult.getResult();

        decrypt = huaweiCrypto.decrypt(cipherResult);
        assertSame(new String(decrypt.getResult()).intern(), "cache");

        Thread.sleep(4000);
        encryptResult = huaweiCrypto.encrypt(new EncryptRequest(encryptionContext, "no_cache".getBytes(ENCODING)));
        cipherResult = encryptResult.getResult();

        decrypt = huaweiCrypto.decrypt(cipherResult);
        assertSame(new String(decrypt.getResult()).intern(), "no_cache");
    }

    @Test
    public void Should_ok_When_CacheExceedMessageLimitTest() throws InterruptedException {
        String str = "hello world";
        Map<String, String> encryptionContext = CommonUtils.getEncryptionContext();

        CacheCryptoMeterialManager cacheCryptoMeterialManager = new CacheCryptoMeterialManager(new LocalDataKeyCache(),
            config);
        cacheCryptoMeterialManager.setMaxByteLimit(50);
        cacheCryptoMeterialManager.setMaxMessageLimit(1);
        cacheCryptoMeterialManager.setSurvivalTime(50000);
        huaweiCrypto.withCryptoMeterialManager(cacheCryptoMeterialManager);

        CryptoResult<byte[]> encryptResult = huaweiCrypto.encrypt(
            new EncryptRequest(encryptionContext, PLAIN_TEXT.getBytes(ENCODING)));
        byte[] cipherResult = encryptResult.getResult();

        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(cipherResult);
        assertSame(new String(decrypt.getResult()).intern(), PLAIN_TEXT);

        Thread.sleep(2000);
        encryptResult = huaweiCrypto.encrypt(new EncryptRequest(encryptionContext, "cache".getBytes(ENCODING)));
        cipherResult = encryptResult.getResult();

        decrypt = huaweiCrypto.decrypt(cipherResult);
        assertSame(new String(decrypt.getResult()).intern(), "cache");

        Thread.sleep(4000);
        encryptResult = huaweiCrypto.encrypt(new EncryptRequest(encryptionContext, "no_cache".getBytes(ENCODING)));
        cipherResult = encryptResult.getResult();

        decrypt = huaweiCrypto.decrypt(cipherResult);
        assertSame(new String(decrypt.getResult()).intern(), "no_cache");
    }

    @Test(expected = HuaweicloudException.class)
    public void Should_Error_When_CacheEncryptExceedByteLimitTest() {
        Map<String, String> encryptionContext = CommonUtils.getEncryptionContext();

        CacheCryptoMeterialManager cacheCryptoMeterialManager = new CacheCryptoMeterialManager(new LocalDataKeyCache(),
            config);
        cacheCryptoMeterialManager.setMaxByteLimit(1);
        cacheCryptoMeterialManager.setMaxMessageLimit(10);
        huaweiCrypto.withCryptoMeterialManager(cacheCryptoMeterialManager);

        CryptoResult<byte[]> encryptResult = huaweiCrypto.encrypt(
            new EncryptRequest(encryptionContext, PLAIN_TEXT.getBytes(ENCODING)));
        byte[] cipherResult = encryptResult.getResult();

        CryptoResult<byte[]> decrypt = huaweiCrypto.decrypt(cipherResult);
        assertSame(new String(decrypt.getResult()).intern(), PLAIN_TEXT);
    }

    @Test(expected = HuaweicloudException.class)
    public void Should_ok_When_KMSCacheTest() throws InterruptedException {
        Map<String, String> encryptionContext = CommonUtils.getEncryptionContext();
        HuaweiConfig tempConfig = HuaweiConfig.builder()
            .sk(EncryptDecryptTest.SECRET_ACCESS_KEY)
            .ak(EncryptDecryptTest.ACCESS_KEY)
            .kmsConfigList(Collections.singletonList(
                new KMSConfig(EncryptDecryptTest.REGION, EncryptDecryptTest.KEYID, EncryptDecryptTest.PROJECT_ID)))
            .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
            .build();
        HuaweiCrypto tempHuaweiCrypto = new HuaweiCrypto(tempConfig);
        tempHuaweiCrypto.withKeyring(new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_MULTI_REGION.getType()));

        CacheCryptoMeterialManager cacheCryptoMeterialManager = new CacheCryptoMeterialManager(new LocalDataKeyCache(),
                tempConfig);
        cacheCryptoMeterialManager.setMaxByteLimit(50);
        cacheCryptoMeterialManager.setSurvivalTime(5000);
        tempHuaweiCrypto.withCryptoMeterialManager(cacheCryptoMeterialManager);

        CryptoResult<byte[]> encryptResult = tempHuaweiCrypto.encrypt(
            new EncryptRequest(encryptionContext, PLAIN_TEXT.getBytes(ENCODING)));
        byte[] cipherResult = encryptResult.getResult();

        CryptoResult<byte[]> decrypt = tempHuaweiCrypto.decrypt(cipherResult);
        assertSame(new String(decrypt.getResult()).intern(), PLAIN_TEXT);

        Thread.sleep(2000);
        encryptResult = tempHuaweiCrypto.encrypt(new EncryptRequest(encryptionContext, "cache".getBytes(ENCODING)));
        cipherResult = encryptResult.getResult();

        decrypt = tempHuaweiCrypto.decrypt(cipherResult);
        assertSame(new String(decrypt.getResult()).intern(), "cache");

        Thread.sleep(4000);
        encryptResult = tempHuaweiCrypto.encrypt(new EncryptRequest(encryptionContext, "no_cache".getBytes(ENCODING)));
        cipherResult = encryptResult.getResult();

        decrypt = tempHuaweiCrypto.decrypt(cipherResult);
        assertSame(new String(decrypt.getResult()).intern(), "no_cache");
    }

}
