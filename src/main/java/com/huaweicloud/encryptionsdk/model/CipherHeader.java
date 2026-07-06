package com.huaweicloud.encryptionsdk.model;

import com.huaweicloud.encryptionsdk.common.Constants;
import com.huaweicloud.encryptionsdk.common.CryptoFactory;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.CipherTamperedException;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.handler.CipherHandler;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * @ClassName CipherHeader
 * @description:
 */
public class CipherHeader {

    private static final String CACHE_ID_ALGORITHM_SM3 = "SM3";

    private byte version = Constants.VERSION;

    private short algorithmId;

    private CryptoAlgorithm algorithm;

    private short encryptionContextByteLength;

    private byte[] encryptionContextByte;

    private byte contentType;

    private Map<String, String> encryptionContext;

    private List<CiphertextDataKey> ciphertextDataKeys;

    /**
     * 密钥胶囊（密钥胶囊模式时使用）
     */
    private KeyCapsule keyCapsule;

    private int keyCapsuleLength;

    private byte cipherDataKeySize;

    private byte ivLength;

    private short headerTagLength;

    private byte[] headerTag;

    private byte[] iv;

    private int contentLength;

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public int getContentLength() {
        return contentLength;
    }

    public void setContentLength(int contentLength) {
        this.contentLength = contentLength;
    }

    public short getHeaderTagLength() {
        return headerTagLength;
    }

    public byte[] getHeaderTag() {
        return headerTag;
    }

    public CryptoAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(CryptoAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public Map<String, String> getEncryptionContext() {
        return encryptionContext;
    }

    public void setEncryptionContext(Map<String, String> encryptionContext) {
        this.encryptionContext = encryptionContext;
    }

    public List<CiphertextDataKey> getCiphertextDataKeys() {
        return ciphertextDataKeys;
    }

    public void setCiphertextDataKeys(List<CiphertextDataKey> ciphertextDataKeys) {
        this.ciphertextDataKeys = ciphertextDataKeys;
    }

    public KeyCapsule getKeyCapsule() {
        return keyCapsule;
    }

    public void setKeyCapsule(KeyCapsule keyCapsule) {
        this.keyCapsule = keyCapsule;
    }

    public CipherHeader() {
    }

    public CipherHeader(CryptoAlgorithm algorithm, Map<String, String> encryptionContext,
        List<CiphertextDataKey> ciphertextDataKeys, SecretKey secretKey)
        throws GeneralSecurityException {
        this(algorithm, encryptionContext, ciphertextDataKeys, secretKey, null);
    }

    public CipherHeader(CryptoAlgorithm algorithm, Map<String, String> encryptionContext,
                        List<CiphertextDataKey> ciphertextDataKeys, SecretKey secretKey, KeyCapsule keyCapsule)
            throws GeneralSecurityException {
        this.algorithm = algorithm;
        this.algorithmId = algorithm.getValue();
        this.encryptionContext = encryptionContext;
        this.encryptionContextByte = Utils.serializeContext(encryptionContext);
        this.encryptionContextByteLength = (short) encryptionContextByte.length;
        this.contentType = 1;
        this.ciphertextDataKeys = ciphertextDataKeys;
        this.cipherDataKeySize = (byte) ciphertextDataKeys.size();
        this.ivLength = (byte) algorithm.getIvLen();
        this.keyCapsule = keyCapsule;
        if (this.keyCapsule != null) {
            version = Constants.VERSION_SUPPORT_KEY_CAPSULE;
        }
        calculateTag(secretKey);
    }

    private void calculateTag(SecretKey secretKey) throws GeneralSecurityException {
        byte[] headerFieldsBytes = serializeAuthenticatedFields();
        if (algorithm == CryptoAlgorithm.SM4_128_CBC_PADDING) {
            headerTag = getDigest(headerFieldsBytes);
            headerTagLength = (short) headerTag.length;
            return;
        }
        CipherHandler cipherHandler = new CipherHandler(algorithm, secretKey, Cipher.ENCRYPT_MODE);
        byte[] headerTagByte = cipherHandler.cipherHeaderData(new byte[0], headerFieldsBytes, Constants.NUM_0,
            Constants.NUM_0);
        int ivLen = cipherHandler.getIv().length;
        byte[] message = new byte[ivLen + headerTagByte.length];
        System.arraycopy(cipherHandler.getIv(), Constants.NUM_0, message, Constants.NUM_0, ivLen);
        System.arraycopy(headerTagByte, Constants.NUM_0, message, ivLen, headerTagByte.length);
        headerTag = message;
        headerTagLength = (short) headerTag.length;
    }

    private byte[] getDigest(byte[] bytes) throws GeneralSecurityException {
        MessageDigest digest = CryptoFactory.getMessageDigest(CACHE_ID_ALGORITHM_SM3);
        if (bytes.length == 0) {
            digest.update((byte) 0);
        } else {
            digest.update(bytes);
        }
        return digest.digest();
    }

    public byte[] serializeAuthenticatedFields() {
        try (ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
            DataOutputStream dataStream = new DataOutputStream(outBytes)) {
            dataStream.writeByte(version);

            dataStream.writeShort(algorithmId);

            dataStream.writeShort(encryptionContextByteLength);
            dataStream.write(encryptionContextByte);

            dataStream.writeByte(cipherDataKeySize);

            for (CiphertextDataKey dataKey : ciphertextDataKeys) {
                dataStream.write(dataKey.toByteArray());
            }

            dataStream.writeByte(contentType);

            dataStream.writeByte(ivLength);

            // V2版本：如果是密钥胶囊模式，序列化密钥胶囊
            if (version == 2 && keyCapsule != null) {
                byte[] keyCapsuleBytes = serializeKeyCapsule(keyCapsule);
                keyCapsuleLength = keyCapsuleBytes.length;
                dataStream.writeInt(keyCapsuleLength);
                dataStream.write(keyCapsuleBytes, 0, keyCapsuleLength);
            }

            return outBytes.toByteArray();
        } catch (IOException e) {
            throw new HuaweicloudException(ErrorMessage.SERIALIZE_EXCEPTION.getMessage(), e);
        }
    }

    /**
     * 序列化密钥胶囊
     */
    private byte[] serializeKeyCapsule(KeyCapsule keyCapsule) throws IOException {
        try (ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
            DataOutputStream dataStream = new DataOutputStream(outBytes)) {

            writeString(dataStream, keyCapsule.getKeyId());
            writeString(dataStream, keyCapsule.getDatakeyCapsule());
            dataStream.writeInt(keyCapsule.getAccessPointType());
            return outBytes.toByteArray();
        }
    }

    private void writeString(DataOutputStream dataStream, String value) throws IOException {
        if (value == null) {
            dataStream.writeInt(-1);
        } else {
            byte[] bytes = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            dataStream.writeInt(bytes.length);
            dataStream.write(bytes);
        }
    }

    private void writeBytes(DataOutputStream dataStream, byte[] value) throws IOException {
        if (value == null) {
            dataStream.writeInt(-1);
        } else {
            dataStream.writeInt(value.length);
            dataStream.write(value);
        }
    }

    public CipherHeader deserializeAuthenticatedFields(DataInputStream dataStream) {

        try {
            version = dataStream.readByte();

            if (version == 1) {
                // V1版本：无密钥胶囊
                deserializeV1Format(dataStream);
            } else if (version >= 2) {
                // V2版本：支持密钥胶囊
                deserializeV2Format(dataStream);
            } else {
                throw new HuaweicloudException(
                    ErrorMessage.CIPHER_TEXT_CHANGED_ERROR.getMessage() + ", unsupported version: " + version);
            }
            return this;
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.DESERIALIZE_EXCEPTION.getMessage(), e);
        }

    }

    /**
     * 反序列化V1格式
     */
    private void deserializeV1Format(DataInputStream dataStream) throws IOException {
        algorithmId = dataStream.readShort();
        this.algorithm = CryptoAlgorithm.getAlgorithm(algorithmId);
        if (this.algorithm == null) {
            throw new HuaweicloudException(
                ErrorMessage.CIPHER_TEXT_CHANGED_ERROR.getMessage() + ",algorithm id is: " + algorithmId);
        }

        encryptionContextByteLength = dataStream.readShort();
        encryptionContextByte = new byte[encryptionContextByteLength];
        int readContext = dataStream.read(encryptionContextByte);
        if (readContext != encryptionContextByte.length) {
            throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
        }
        this.encryptionContext = Utils.deserializeContext(encryptionContextByte);

        this.cipherDataKeySize = dataStream.readByte();
        if (this.cipherDataKeySize < 0) {
            throw new HuaweicloudException(ErrorMessage.NOT_FOUND_CIPHER_TEXT_DATA_KEY.getMessage());
        }

        this.ciphertextDataKeys = new ArrayList<>(cipherDataKeySize);
        int ciphertextDataKeyCount = 0;
        while (ciphertextDataKeyCount < cipherDataKeySize) {
            CiphertextDataKey ciphertextDataKey = new CiphertextDataKey();
            ciphertextDataKey.byteArrayToBean(dataStream);
            ciphertextDataKeys.add(ciphertextDataKey);
            ciphertextDataKeyCount++;
        }

        contentType = dataStream.readByte();
        ivLength = dataStream.readByte();
        headerTagLength = dataStream.readShort();
        headerTag = new byte[headerTagLength];
        int readHeader = dataStream.read(headerTag);
        if (readHeader != headerTag.length) {
            throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
        }
    }

    /**
     * 反序列化V2格式
     */
    private void deserializeV2Format(DataInputStream dataStream) throws IOException {
        algorithmId = dataStream.readShort();
        this.algorithm = CryptoAlgorithm.getAlgorithm(algorithmId);
        if (this.algorithm == null) {
            throw new HuaweicloudException(
                ErrorMessage.CIPHER_TEXT_CHANGED_ERROR.getMessage() + ",algorithm id is: " + algorithmId);
        }

        encryptionContextByteLength = dataStream.readShort();
        encryptionContextByte = new byte[encryptionContextByteLength];
        int readContext = dataStream.read(encryptionContextByte);
        if (readContext != encryptionContextByte.length) {
            throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
        }
        this.encryptionContext = Utils.deserializeContext(encryptionContextByte);

        this.cipherDataKeySize = dataStream.readByte();

        // 读取密文数据密钥
        if (this.cipherDataKeySize < 0) {
            throw new HuaweicloudException(ErrorMessage.NOT_FOUND_CIPHER_TEXT_DATA_KEY.getMessage());
        }
        this.ciphertextDataKeys = new ArrayList<>(cipherDataKeySize);
        int ciphertextDataKeyCount = 0;
        while (ciphertextDataKeyCount < cipherDataKeySize) {
            CiphertextDataKey ciphertextDataKey = new CiphertextDataKey();
            ciphertextDataKey.byteArrayToBean(dataStream);
            ciphertextDataKeys.add(ciphertextDataKey);
            ciphertextDataKeyCount++;
        }

        contentType = dataStream.readByte();
        ivLength = dataStream.readByte();

        // 如果是密钥胶囊模式，读取密钥胶囊
        if (version == 2) {
            keyCapsuleLength = dataStream.readInt();
            if (keyCapsuleLength > 0) {
                byte[] keyCapsuleBytes = new byte[keyCapsuleLength];
                int readKeyCapsule = dataStream.read(keyCapsuleBytes);
                if (readKeyCapsule != keyCapsuleLength) {
                    throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
                }
                this.keyCapsule = deserializeKeyCapsule(keyCapsuleBytes);
            }
        }

        headerTagLength = dataStream.readShort();
        headerTag = new byte[headerTagLength];
        int readHeader = dataStream.read(headerTag);
        if (readHeader != headerTag.length) {
            throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
        }
    }

    /**
     * 反序列化密钥胶囊
     */
    private KeyCapsule deserializeKeyCapsule(byte[] bytes) throws IOException {
        try (java.io.ByteArrayInputStream inputStream = new java.io.ByteArrayInputStream(bytes);
            DataInputStream dataStream = new DataInputStream(inputStream)) {
            String keyId = readString(dataStream);
            String datakeyCapsule = readString(dataStream);
            int accessPointType = dataStream.readInt();

            return KeyCapsule.builder()
                .keyId(keyId)
                .datakeyCapsule(datakeyCapsule)
                .accessPointType(accessPointType)
                .build();
        }
    }

    private String readString(DataInputStream dataStream) throws IOException {
        int length = dataStream.readInt();
        if (length < 0) {
            return null;
        }
        byte[] bytes = new byte[length];
        int read = dataStream.read(bytes);
        if (read != length) {
            throw new IOException("Failed to read string");
        }
        return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
    }

    public void verifyHeader(CipherHandler cipherHandler) {
        try {
            this.headerTag = getHeaderTag();
            byte[] headerFieldsBytes = serializeAuthenticatedFields();
            if (algorithm == CryptoAlgorithm.SM4_128_CBC_PADDING) {
                byte[] digest = getDigest(headerFieldsBytes);
                String encryptHeaderAuthTag = Utils.bytesToHex(headerTag);
                String decryptHeaderAuthTag = Utils.bytesToHex(digest);
                if (Utils.isEmpty(encryptHeaderAuthTag) && Utils.isEmpty(decryptHeaderAuthTag)) {
                    return;
                }
                if (Utils.isEmpty(encryptHeaderAuthTag) || Utils.isEmpty(decryptHeaderAuthTag)) {
                    throw new CipherTamperedException(ErrorMessage.TAMPERED_EXCEPTION.getMessage());
                }
                if (!encryptHeaderAuthTag.equals(decryptHeaderAuthTag)) {
                    throw new CipherTamperedException(ErrorMessage.TAMPERED_EXCEPTION.getMessage());
                }
                return;
            }
            cipherHandler.cipherHeaderData(headerTag, headerFieldsBytes, algorithm.getIvLen(),
                getHeaderTag().length - algorithm.getIvLen());
        } catch (Exception e) {
            throw new CipherTamperedException(ErrorMessage.TAMPERED_EXCEPTION.getMessage(), e);
        }
    }

    public byte[] serializeFileFields() {
        try (ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
            DataOutputStream dataStream = new DataOutputStream(outBytes)) {
            dataStream.write(iv);
            dataStream.writeLong(contentLength);
            return outBytes.toByteArray();
        } catch (IOException e) {
            throw new HuaweicloudException(ErrorMessage.SERIALIZE_EXCEPTION.getMessage(), e);
        }
    }

    public int getFileHeaderLength(CryptoAlgorithm algorithm) {
        return algorithm.getIvLen() + Long.SIZE / Byte.SIZE;
    }

    public void deserializeFileFields(byte[] headerBytes, CryptoAlgorithm algorithm) {
        this.iv = Arrays.copyOfRange(headerBytes, 0, algorithm.getIvLen());
        this.contentLength = (int) Utils.byteToLong(
            Arrays.copyOfRange(headerBytes, algorithm.getIvLen(), headerBytes.length));
    }
}
