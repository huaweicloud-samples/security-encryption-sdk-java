package com.huaweicloud.encryptionsdk.handler;

import com.huaweicloud.encryptionsdk.common.CountingOutputStream;
import com.huaweicloud.encryptionsdk.common.Constants;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.model.CipherBody;
import com.huaweicloud.encryptionsdk.model.CipherHeader;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.DataMaterials;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Map;

/**
 * @description: 加密处理器，负责数据加解密数据拆分合并等处理
 */
public class DefaultCryptoHandler implements CryptoHadler {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultCryptoHandler.class);

    private SerializeHandler serializeHandler;

    public DefaultCryptoHandler() {
        serializeHandler = new DefaultSerializeHandler();
    }

    @Override
    public CryptoResult<byte[]> encrypt(EncryptRequest request, DataKeyMaterials dataKeyMaterials)
        throws GeneralSecurityException {
        CipherHandler cipherHandler = new CipherHandler(dataKeyMaterials.getCryptoAlgorithm(),
            dataKeyMaterials.getPlaintextDataKey(), Cipher.ENCRYPT_MODE);
        byte[] encryptedData = cipherHandler.cipherData(request.getPlainText(), request.getEncryptionContext(), 0,
            request.getPlainText().length);
        int tagLen = dataKeyMaterials.getCryptoAlgorithm() == CryptoAlgorithm.SM4_128_CBC_PADDING
            ? 0
            : dataKeyMaterials.getCryptoAlgorithm().getTagLen();
        byte[] cipherText = new byte[encryptedData.length - tagLen];
        byte[] authTag = new byte[tagLen];
        if (tagLen != 0) {
            System.arraycopy(encryptedData, 0, cipherText, 0, encryptedData.length - tagLen);
            System.arraycopy(encryptedData, cipherText.length, authTag, 0, tagLen);
        } else {
            cipherText = encryptedData;
        }
        CipherHeader cipherHeader = new CipherHeader(dataKeyMaterials.getCryptoAlgorithm(),
            dataKeyMaterials.getEncryptionContexts(), dataKeyMaterials.getCiphertextDataKeys(),
            dataKeyMaterials.getPlaintextDataKey(), dataKeyMaterials.getKeyCapsule());
        CipherBody cipherBody = new CipherBody(cipherHandler.getIv(), cipherText, cipherText.length, authTag);
        DataMaterials dataMaterials = new DataMaterials(cipherBody, cipherHeader);
        byte[] serializedData = serializeHandler.serialize(dataMaterials);
        return new CryptoResult<>(serializedData, cipherHeader, cipherText.length);
    }

    @Override
    public CryptoResult<byte[]> decrypt(byte[] cipherText, DataKeyMaterials dataKeyMaterials) {
        DataMaterials dataMaterials = serializeHandler.deserialize(cipherText);
        CipherHeader headers = dataMaterials.getHeaders();
        byte[] headerTag = headers.getHeaderTag();
        byte[] headerTagIV = new byte[headers.getAlgorithm().getIvLen()];
        System.arraycopy(headerTag, Constants.NUM_0, headerTagIV, Constants.NUM_0, headerTagIV.length);
        CipherHandler cipherHandler = new CipherHandler(dataKeyMaterials.getCryptoAlgorithm(),
            dataKeyMaterials.getPlaintextDataKey(), Cipher.DECRYPT_MODE);
        cipherHandler.setIv(headerTagIV);
        headers.verifyHeader(cipherHandler);
        CipherBody cipherBody = dataMaterials.getCipherBody();
        if (cipherBody == null) {
            throw new HuaweicloudException(ErrorMessage.CIPHER_TEXT_CHANGED_ERROR.getMessage());
        }
        byte[] iv = cipherBody.getIv();
        byte[] encryptedContent = cipherBody.getEncryptedContent();
        byte[] authTag = cipherBody.getAuthTag();
        if (dataMaterials.getHeaders().getAlgorithm() != CryptoAlgorithm.SM4_128_CBC_PADDING
            && authTag.length != dataMaterials.getHeaders().getAlgorithm().getTagLen()) {
            throw new IllegalArgumentException("Invalid tag length: " + authTag.length);
        }
        byte[] result = new byte[encryptedContent.length + authTag.length + iv.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encryptedContent, 0, result, iv.length, encryptedContent.length);
        System.arraycopy(authTag, 0, result, encryptedContent.length + iv.length, authTag.length);
        cipherHandler.setIv(iv);
        byte[] decryptData = cipherHandler.cipherData(result, dataKeyMaterials.getEncryptionContexts(), iv.length,
            result.length - iv.length);
        return new CryptoResult<>(decryptData, dataMaterials.getHeaders());
    }

    @Override
    public CryptoResult<OutputStream> encrypt(InputStream inputStream, OutputStream outputStream,
        DataKeyMaterials dataKeyMaterials, Map<String, String> encryptionContext)
        throws IOException, GeneralSecurityException {
        CountingOutputStream countingStream = new CountingOutputStream(outputStream);
        CipherHeader cipherHeader = new CipherHeader(dataKeyMaterials.getCryptoAlgorithm(),
            dataKeyMaterials.getEncryptionContexts(), dataKeyMaterials.getCiphertextDataKeys(),
            dataKeyMaterials.getPlaintextDataKey(), dataKeyMaterials.getKeyCapsule());
        byte[] authenticatedFields = cipherHeader.serializeAuthenticatedFields();
        countingStream.write(shortToByte((short) (authenticatedFields.length + 2 + cipherHeader.getHeaderTagLength())));
        countingStream.write(authenticatedFields);
        countingStream.write(shortToByte(cipherHeader.getHeaderTagLength()));
        countingStream.write(cipherHeader.getHeaderTag());
        FileEncryptHandler fileEncryptHandler = new FileEncryptHandler(dataKeyMaterials.getCryptoAlgorithm(),
            dataKeyMaterials.getPlaintextDataKey(), Cipher.ENCRYPT_MODE);
        fileEncryptHandler.processByte(inputStream, countingStream, dataKeyMaterials.getEncryptionContexts(),
            Constants.BLOCK_SIZE);
        return new CryptoResult<>(countingStream, cipherHeader, countingStream.getBytesWritten());
    }

    @Override
    public CryptoResult<OutputStream> decrypt(InputStream inputStream, OutputStream outputStream,
        DataKeyMaterials dataKeyMaterials) throws IOException {
        CountingOutputStream countingStream = new CountingOutputStream(outputStream);
        FileDecryptHandler fileDecryptHandler = new FileDecryptHandler(dataKeyMaterials.getCryptoAlgorithm(),
            dataKeyMaterials.getPlaintextDataKey(), Cipher.DECRYPT_MODE);
        fileDecryptHandler.processByte(inputStream, countingStream, dataKeyMaterials.getEncryptionContexts(),
            Constants.BLOCK_SIZE);
        return new CryptoResult<>(countingStream, null, countingStream.getBytesWritten());
    }

    private byte[] shortToByte(short num) {
        return ByteBuffer.allocate(Short.SIZE / Byte.SIZE).putShort(num).array();
    }

}
