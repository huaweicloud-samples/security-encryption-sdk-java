package com.huaweicloud.encryptionsdk.example;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.HuaweiCrypto;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import com.huaweicloud.encryptionsdk.util.CommonUtils;

import org.apache.commons.lang3.Validate;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;

/**
 * @description: 本示例演示使用本地对称主密钥，算法类型为 AES 密钥环 对本地文件进行加密，然后再解密。
 * </p>
 * 你需要提供一个 KMS 对称秘钥和待加密路径文件、加密后的文件路劲、解密加密后的文件路径作为参数。
 */
@Slf4j
public class FileEncryptionExample {

    public static void main(String[] args) {
        // 1. 获取参数传入的对称密钥以及需要加密、解密的文件路径
        String symemetryKey = args[0];
        // 需要加密时的源文件路劲
        String sourceFilePath = args[1];
        // 加密后的文件路劲
        String targetFilePath = args[2];
        // 解密经过加密后的文件路劲
        String backupFilePath = args[3];

        // 2. 初始化加解密相关配置及加密算法
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
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

        // 7. 加密文件数据
        // fileInputStream 源文件对应的输入流；fileOutputStream 加密后文件对应的输出流
        try (FileInputStream fileInputStream = new FileInputStream(sourceFilePath);
            FileOutputStream fileOutputStream = new FileOutputStream(targetFilePath)) {
            // 文件加密
            huaweiCrypto.encrypt(fileInputStream, fileOutputStream, map);
        } catch (Exception e) {
            log.error(e.getMessage());
        }

        // 8. 解密加密后的文件数据
        // fileInputStream 加密后文件对应的输入流；fileOutputStream 解密加密后的文件对应的输出流
        try (FileInputStream in = new FileInputStream(targetFilePath);
            FileOutputStream out = new FileOutputStream(backupFilePath)) {
            // 文件解密
            huaweiCrypto.decrypt(in, out);
        } catch (Exception e) {
            log.error(e.getMessage());
        }

        // 9. 验证解密后的数据是否和原文件数据一致
        Validate.isTrue(compareFile(sourceFilePath, backupFilePath));
    }

    /**
     * 对比2个路径文件内容是否一致
     * @param sourceFilePath 源文件路劲
     * @param targetFilePath 目标文件路径
     * @return 一致返回 true，否则返回 false
     */
    public static boolean compareFile(String sourceFilePath, String targetFilePath) {
        File sourceFile = new File(sourceFilePath);
        File targetFile = new File(targetFilePath);
        if (sourceFile.length() != targetFile.length()) {
            return false;
        }

        try (FileInputStream sourceStream = new FileInputStream(sourceFile);
            FileInputStream targetStream = new FileInputStream(sourceFile)) {
            byte[] sourceBytes = new byte[1024];
            byte[] targetBytes = new byte[1024];

            int sourceBytesRead;
            int targetBytesRead;
            while ((sourceBytesRead = sourceStream.read(sourceBytes)) != -1) {
                targetBytesRead = targetStream.read(targetBytes);

                if (sourceBytesRead != targetBytesRead || !isEqual(sourceBytes, targetBytes, sourceBytesRead)) {
                    return false;
                }
            }
        } catch (Exception e) {
            log.error(e.getMessage());
        }
        return true;
    }

    /**
     * 对比 2 个字节数组的前 n 个字节是否一致
     * @param sourceBytes 源字节数组
     * @param targetBytes 目标字节数组
     * @param bytesRead 需要对比字节个数
     * @return 一致返回 true，否则返回 false
     */
    public static boolean isEqual(byte[] sourceBytes, byte[] targetBytes, int bytesRead) {
        for (int i = 0; i < bytesRead; i++) {
            if (sourceBytes[i] != targetBytes[i]) {
                return false;
            }
        }
        return true;
    }
}
