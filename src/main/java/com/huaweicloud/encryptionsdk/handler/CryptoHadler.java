package com.huaweicloud.encryptionsdk.handler;

import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.util.Map;

/**
 * 加解密处理器，定义加解密操作
 */
public interface CryptoHadler {

    /**
     * @return com.huaweicloud.encryptionsdk.model.CryptoResult<byte [ ]>
     * @Description ：数据加密
     * @Param [request, dataKeyMaterials]
     * request：加密请求，封装了加密数据明文和加密上下文材料
     * dataKeyMaterials：数据密钥和算法等加密必要信息
     **/
    CryptoResult<byte[]> encrypt(EncryptRequest request, DataKeyMaterials dataKeyMaterials)
        throws GeneralSecurityException;

    /**
     * @return com.huaweicloud.encryptionsdk.model.CryptoResult<byte [ ]>
     * @Description ：数据解密
     * @Param [cipherText, dataKeyMaterials]
     * cipherText：密文
     * dataKeyMaterials：数据密钥和算法等加密必要信息
     **/
    CryptoResult<byte[]> decrypt(byte[] cipherText, DataKeyMaterials dataKeyMaterials);

    /**
     * @return com.huaweicloud.encryptionsdk.model.CryptoResult<java.io.OutputStream>
     * @Description ：数据流加密
     * @Param [inputStream, outputStream, dataKeyMaterials, encryptionContext]
     * inputStream：明文输入流
     * outputStream：密文输出流
     * dataKeyMaterials：数据密钥和算法等加密必要信息
     * encryptionContext：加密上下文
     **/
    CryptoResult<OutputStream> encrypt(InputStream inputStream, OutputStream outputStream,
        DataKeyMaterials dataKeyMaterials, Map<String, String> encryptionContext)
        throws IOException, GeneralSecurityException;

    /**
     * @return com.huaweicloud.encryptionsdk.model.CryptoResult<java.io.OutputStream>
     * @Description
     * @Param [inputStream, outputStream, dataKeyMaterials]
     * inputStream：密文输入流
     * outputStream：明文输出流
     **/
    CryptoResult<OutputStream> decrypt(InputStream inputStream, OutputStream outputStream,
        DataKeyMaterials dataKeyMaterials) throws IOException;

}
