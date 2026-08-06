package com.huaweicloud.encryptionsdk.handler;

import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

/**
 * @description: 文件加密处理器
 */
public class FileEncryptHandler {

    private int mode;

    private CryptoAlgorithm algorithm;

    private SecretKey secretKey;

    public FileEncryptHandler(CryptoAlgorithm algorithm, SecretKey secretKey, int mode) {
        this.mode = mode;
        this.algorithm = algorithm;
        this.secretKey = secretKey;
    }

    public void processByte(InputStream inputStream, OutputStream outputStream, Map<String, String> encryptionContext,
        int blockSize) throws IOException {
        byte[] readBytes = new byte[blockSize];
        int readLen = 0;
        CipherHandler cipherHandler = new CipherHandler(algorithm, secretKey, mode);
        byte[] serializedContext = Utils.serializeContext(encryptionContext);
        while ((readLen = inputStream.read(readBytes)) != -1) {
            cipherHandler.reSetIv();
            cipherHandler.processEncryptByte(readBytes, readLen, outputStream, serializedContext);
        }
    }

}
