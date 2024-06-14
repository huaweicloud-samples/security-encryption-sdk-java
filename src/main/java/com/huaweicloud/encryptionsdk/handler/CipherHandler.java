package com.huaweicloud.encryptionsdk.handler;

import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.CipherDataException;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.model.CipherHeader;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;

/**
 * @description: 加解密器，具体的加密算法操作实现
 */
public class CipherHandler {

    private Cipher cipher;

    private byte[] iv;

    private int mode;

    private CryptoAlgorithm algorithm;

    private SecretKey secretKey;

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public int getMode() {
        return mode;
    }

    public void setMode(int mode) {
        this.mode = mode;
    }

    private static final SecureRandom RANDOM;

    static {
        try {
            RANDOM = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new HuaweicloudException(e);
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * @return
     * @Description ：加解密处理器初始化
     * @Param [algorithm, secretKey, mode]
     * algorithm：算法类型
     * secretKey：密钥
     * mode：操作类型，包括加密和解密
     **/
    public CipherHandler(CryptoAlgorithm algorithm, SecretKey secretKey, int mode) {
        this.mode = mode;
        this.secretKey = secretKey;
        this.algorithm = algorithm;
        try {
            byte[] algorithmIv = getIv(algorithm);
            this.iv = algorithmIv;
            this.cipher = Cipher.getInstance(algorithm.getCryptoAlg(), BouncyCastleProvider.PROVIDER_NAME);
        } catch (Exception e) {
            throw new CipherDataException(e);
        }
    }

    private byte[] getIv(CryptoAlgorithm algorithm) {
        byte[] algorithmIv = new byte[algorithm.getIvLen()];
        RANDOM.nextBytes(algorithmIv);
        return algorithmIv;
    }

    public void reSetIv() {
        this.iv = getIv(algorithm);
    }

    /**
     * @return byte[]
     * @Description ：数据加密
     * @Param [plainText, encryptionContext, offset, len]
     * plainText：明文或者密文数据
     * encryptionContext：加密上下文
     * offset：加密或解密起点下标
     * len：加密或解密数据长度
     **/
    public byte[] cipherData(byte[] plainText, Map<String, String> encryptionContext, int offset, int len) {
        try {
            AlgorithmParameterSpec params = getParameterSpec(plainText);
            cipher.init(mode, secretKey, params);
            if (algorithm != CryptoAlgorithm.SM4_128_CBC_PADDING) {
                cipher.updateAAD(Utils.serializeContext(encryptionContext));
            }
            return cipher.doFinal(plainText, offset, len);
        } catch (Exception e) {
            throw new CipherDataException(ErrorMessage.CIPHER_EXCEPTION.getMessage(), e);
        }
    }

    public byte[] cipherHeaderData(byte[] content, byte[] encryptionContext, int offset, int len) {
        try {
            AlgorithmParameterSpec params = null;
            String strs = algorithm.getCryptoMode();
            if ("CBC".equalsIgnoreCase(strs)) {
                params = new IvParameterSpec(iv);
            }
            if ("GCM".equalsIgnoreCase(strs)) {
                params = new GCMParameterSpec(algorithm.getTagLen() * 8, iv);
            }
            cipher.init(mode, secretKey, params);
            if (algorithm != CryptoAlgorithm.SM4_128_CBC_PADDING) {
                cipher.updateAAD(encryptionContext);
            }
            return cipher.doFinal(content, offset, len);
        } catch (Exception e) {
            throw new CipherDataException(ErrorMessage.CIPHER_EXCEPTION.getMessage(), e);
        }
    }

    private AlgorithmParameterSpec getParameterSpec(byte[] plainText) {
        AlgorithmParameterSpec params = null;
        String strs = algorithm.getCryptoMode();
        if ("CBC".equalsIgnoreCase(strs)) {
            params = new IvParameterSpec(iv);
            return params;
        }
        if (mode == Cipher.DECRYPT_MODE && "GCM".equalsIgnoreCase(strs)) {
            params = new GCMParameterSpec(algorithm.getTagLen() * 8, plainText, 0, algorithm.getIvLen());
        } else {
            params = new GCMParameterSpec(algorithm.getTagLen() * 8, iv);
        }
        return params;
    }

    /**
     * @return byte[]
     * @Description ：加密流数据
     * @Param [readBytes, readLen, outputStream, encryptionContext]
     * readBytes：流中读取的明文字节数组
     * readLen：需要加密的数据长度
     * outputStream：密文输出流
     * encryptionContext：加密上下文
     **/
    public byte[] processEncryptByte(byte[] readBytes, int readLen, OutputStream outputStream,
        Map<String, String> encryptionContext) {
        try {
            initCipher();
            if (algorithm != CryptoAlgorithm.SM4_128_CBC_PADDING) {
                cipher.updateAAD(Utils.serializeContext(encryptionContext));
            }
            byte[] bytes = cipher.doFinal(readBytes, 0, readLen);
            CipherHeader cipherHeader = new CipherHeader();
            cipherHeader.setIv(iv);
            cipherHeader.setContentLength(bytes.length);
            byte[] headerByte = cipherHeader.serializeFileFields();
            outputStream.write(headerByte);
            outputStream.write(bytes);
            return bytes;
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.PROCESS_FILE_ERROR.getMessage(), e);
        }
    }

    /**
     * @return byte[]
     * @Description ：解密流数据
     * @Param [readBytes, readLen, outputStream, encryptionContext]
     * readBytes：流中读取的密文字节数组
     * readLen：需要解密的数据长度
     * outputStream：明文输出流
     * encryptionContext：加密上下文
     **/
    public byte[] processDecryptByte(byte[] readBytes, int readLen, OutputStream outputStream,
        Map<String, String> encryptionContext) {
        try {
            initCipher();
            if (algorithm != CryptoAlgorithm.SM4_128_CBC_PADDING) {
                cipher.updateAAD(Utils.serializeContext(encryptionContext));
            }
            byte[] bytes = cipher.doFinal(readBytes, 0, readLen);
            outputStream.write(bytes);
            return bytes;
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.PROCESS_FILE_ERROR.getMessage(), e);
        }
    }

    private void initCipher() throws InvalidAlgorithmParameterException, InvalidKeyException {
        AlgorithmParameterSpec params = null;
        String strs = algorithm.getCryptoMode();
        if ("CBC".equalsIgnoreCase(strs)) {
            params = new IvParameterSpec(iv);
        } else {
            params = new GCMParameterSpec(algorithm.getTagLen() * 8, iv);
        }
        cipher.init(mode, secretKey, params);
    }
}
