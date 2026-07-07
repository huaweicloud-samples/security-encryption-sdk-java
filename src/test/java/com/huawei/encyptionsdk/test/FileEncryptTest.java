package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.cache.LocalDataKeyCache;
import com.huaweicloud.encryptionsdk.common.FilePathForExampleConstants;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.meterialmanager.CacheCryptoMeterialManager;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import com.huaweicloud.encryptionsdk.util.CommonUtils;
import org.apache.commons.codec.DecoderException;
import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Map;

import static org.junit.Assert.assertTrue;

/**
 * @author zc
 * @ClassName FileEncryptTest
 * @description:
 * @datetime 2022年 09月 24日 9:13
 */
public class FileEncryptTest {

    @Test
    public void Should_ok_When_RawRSATXTFileEncrypt() throws NoSuchAlgorithmException, IOException, DecoderException {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
            .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_RSA.getType());
        keyring.setPrivateKey(
            Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PRI_FILE_PATH)));
        keyring.setPublicKey(
            Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PUB_FILE_PATH)));

        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = CommonUtils.getEncryptoMap();
        File encryptedFile = File.createTempFile("128bit", ".encrypted");
        File decryptedFile = File.createTempFile("128bit", ".decrypted");
        encryptedFile.deleteOnExit();
        decryptedFile.deleteOnExit();
        try (FileInputStream fileInputStream = new FileInputStream(FilePathForExampleConstants.BIT_128_FILE_PATH);
            FileOutputStream fileOutputStream = new FileOutputStream(encryptedFile)) {
            huaweiCrypto.encrypt(fileInputStream, fileOutputStream, map);
        }
        try (FileInputStream in = new FileInputStream(encryptedFile);
            FileOutputStream out = new FileOutputStream(decryptedFile)) {
            huaweiCrypto.decrypt(in, out);
        }
        assertTrue(encryptedFile.length() > 0);
        assertTrue(decryptedFile.length() > 0);
    }

    @Test
    public void Should_ok_When_RawRSAPPTFileEncrypt() throws NoSuchAlgorithmException, IOException, DecoderException {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
            .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_RSA.getType());
        keyring.setPrivateKey(
            Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PRI_FILE_PATH)));
        keyring.setPublicKey(
            Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PUB_FILE_PATH)));

        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = CommonUtils.getEncryptoMap();
        File encryptedFile = File.createTempFile("test", ".encrypted.txt");
        File decryptedFile = File.createTempFile("test", ".decrypted.txt");
        encryptedFile.deleteOnExit();
        decryptedFile.deleteOnExit();
        try (FileInputStream fileInputStream = new FileInputStream(FilePathForExampleConstants.TEST_PPT_FILE_PATH);
            FileOutputStream fileOutputStream = new FileOutputStream(encryptedFile)) {
            huaweiCrypto.encrypt(fileInputStream, fileOutputStream, map);
        }
        try (FileInputStream in = new FileInputStream(encryptedFile);
            FileOutputStream out = new FileOutputStream(decryptedFile)) {
            huaweiCrypto.decrypt(in, out);
        }
        assertTrue(encryptedFile.length() > 0);
        assertTrue(decryptedFile.length() > 0);
    }

    @Test
    public void Should_ok_When_RawAESPPTFileEncrypt() throws NoSuchAlgorithmException, IOException, DecoderException {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
            .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_AES.getType());
        keyring.setSymmetricKey(
            Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_256_FILE_PATH)));
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = CommonUtils.getEncryptoMap();
        File encryptedFile = File.createTempFile("test", ".encrypted.txt");
        File decryptedFile = File.createTempFile("test", ".decrypted.txt");
        encryptedFile.deleteOnExit();
        decryptedFile.deleteOnExit();
        try (FileInputStream fileInputStream = new FileInputStream(FilePathForExampleConstants.TEST_PPT_FILE_PATH);
            FileOutputStream fileOutputStream = new FileOutputStream(encryptedFile)) {
            huaweiCrypto.encrypt(fileInputStream, fileOutputStream, map);
        }
        try (FileInputStream in = new FileInputStream(encryptedFile);
            FileOutputStream out = new FileOutputStream(decryptedFile)) {
            huaweiCrypto.decrypt(in, out);
        }
        assertTrue(encryptedFile.length() > 0);
        assertTrue(decryptedFile.length() > 0);
    }

    @Test
    public void Should_ok_When_CacheDataKeyFileEncrypt()
        throws NoSuchAlgorithmException, IOException, DecoderException {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
            .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_AES.getType());
        keyring.setSymmetricKey(
            Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_256_FILE_PATH)));
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        CacheCryptoMeterialManager cacheCryptoMeterialManager = new CacheCryptoMeterialManager(new LocalDataKeyCache(),
            huaweiConfig);
        cacheCryptoMeterialManager.setMaxByteLimit(5000000);
        cacheCryptoMeterialManager.setSurvivalTime(10000);
        huaweiCrypto.withCryptoMeterialManager(cacheCryptoMeterialManager);
        Map<String, String> map = CommonUtils.getEncryptoMap();
        File encryptedFile = File.createTempFile("test", ".encrypted.txt");
        File decryptedFile = File.createTempFile("test", ".decrypted.txt");
        File encryptedCacheFile = File.createTempFile("test", ".encrypted.Cache.txt");
        File decryptedCacheFile = File.createTempFile("test", ".decrypted.Cache.txt");
        encryptedFile.deleteOnExit();
        decryptedFile.deleteOnExit();
        encryptedCacheFile.deleteOnExit();
        decryptedCacheFile.deleteOnExit();
        try (FileInputStream fileInputStream = new FileInputStream(FilePathForExampleConstants.TEST_PPT_FILE_PATH);
            FileOutputStream fileOutputStream = new FileOutputStream(encryptedFile)) {
            huaweiCrypto.encrypt(fileInputStream, fileOutputStream, map);
        }
        try (FileInputStream in = new FileInputStream(encryptedFile);
            FileOutputStream out = new FileOutputStream(decryptedFile)) {
            huaweiCrypto.decrypt(in, out);
        }
        try (
            FileInputStream fileInputStreamCache = new FileInputStream(FilePathForExampleConstants.TEST_PPT_FILE_PATH);
            FileOutputStream fileOutputStreamCache = new FileOutputStream(encryptedCacheFile)) {
            huaweiCrypto.encrypt(fileInputStreamCache, fileOutputStreamCache, map);

        }
        try (FileInputStream inCache = new FileInputStream(encryptedCacheFile);
            FileOutputStream outCache = new FileOutputStream(decryptedCacheFile)) {
            huaweiCrypto.decrypt(inCache, outCache);
        }
        assertTrue(encryptedFile.length() > 0);
        assertTrue(decryptedFile.length() > 0);
        assertTrue(encryptedCacheFile.length() > 0);
        assertTrue(decryptedCacheFile.length() > 0);
    }

    /**
     * jar包中无大文件，打包时单元测试无法通过，故暂不开启 @Test
     */
    public void Should_ok_When_FileSizeGreaterThanOneGB()
        throws NoSuchAlgorithmException, IOException, DecoderException {
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
            .build();
        RawKeyring keyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_AES.getType());
        keyring.setSymmetricKey(
            Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_128_FILE_PATH)));
        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(huaweiConfig).withKeyring(keyring);
        Map<String, String> map = CommonUtils.getEncryptoMap();
        Long startTime = System.currentTimeMillis();
        try (FileInputStream fileInputStream = new FileInputStream("D:\\test.rar");
            FileOutputStream fileOutputStream = new FileOutputStream("D:\\test.encrypted.rar")) {
            huaweiCrypto.encrypt(fileInputStream, fileOutputStream, map);
            long encryptTime = System.currentTimeMillis() - startTime;
            System.out.println(encryptTime);
        }
        try (FileInputStream in = new FileInputStream("D:\\test.encrypted.rar");
            FileOutputStream out = new FileOutputStream("D:\\test.decrypted.rar")) {
            huaweiCrypto.decrypt(in, out);
            // 解密
            long decryptTime = System.currentTimeMillis() - startTime;
            System.out.println(decryptTime);
        }
    }
}
