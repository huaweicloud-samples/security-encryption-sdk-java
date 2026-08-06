package com.huaweicloud.encryptionsdk.model;

import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.model.enums.KeyProviderEnum;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Ciphertext DataKey
 */
public class CiphertextDataKey {

    private int keyProviderLength;

    /**
     * 标识符，用来区别数据密钥生成类型
     */
    private byte[] keyProvider;

    private byte[] dataKey;

    private short dataKeyLength;

    private int keyInformationLength;

    private byte[] keyInformation = new byte[0];

    private byte[] keyId;

    private byte[] region;

    private byte[] projectId;

    private byte[] endPoint;

    private Discovery discovery;

    private int totalLength;

    public boolean isDiscovery() {
        return discovery.isDiscovery;
    }

    public CiphertextDataKey(byte[] dataKey) {
        this.dataKey = dataKey;
        this.dataKeyLength = (short) dataKey.length;
        this.keyProvider = KeyProviderEnum.LOCAL_PROVIDER.getName().getBytes(StandardCharsets.UTF_8);
        this.keyProviderLength = keyProvider.length;
        this.discovery = Discovery.NO_DISCOVERY;
        this.keyInformation = buildKeyInformation(Discovery.NO_DISCOVERY);
        this.keyInformationLength = keyInformation.length;

        /**
         * 总长度包括各类信息数组的长度和长度数字对应的字节数，
         * 如datakey数组和dataKeyLength对应的short数字的转换成的字节数组
         * 用于反序列化时，根据dataKeyLength确定dataKey的数组长度
         * 其中dataKeyLength为short，占2个字节，keyInformationLength和keyProviderLength
         * 为byte，占一个字节，固需要在最后加4个byte长度
         */
        this.totalLength = dataKeyLength + keyProviderLength + keyInformationLength + 4;
    }

    public CiphertextDataKey() {
    }

    public CiphertextDataKey(byte[] dataKey, KMSConfig kmsConfig) {
        this.dataKey = dataKey;
        this.dataKeyLength = (short) dataKey.length;
        if (kmsConfig == null) {
            this.keyProvider = KeyProviderEnum.KMS_PROVIDER.getName().getBytes(StandardCharsets.UTF_8);
            this.keyProviderLength = keyProvider.length;
            this.discovery = Discovery.NO_DISCOVERY;
            this.keyInformation = buildKeyInformation(Discovery.NO_DISCOVERY);
            this.keyInformationLength = keyInformation.length;
        } else {
            this.keyId = Optional.ofNullable(kmsConfig.getKeyId()).orElse("").getBytes(StandardCharsets.UTF_8);
            this.region = Optional.ofNullable(kmsConfig.getRegion()).orElse("").getBytes(StandardCharsets.UTF_8);
            this.projectId = Optional.ofNullable(kmsConfig.getProjectId()).orElse("").getBytes(StandardCharsets.UTF_8);
            this.endPoint = Optional.ofNullable(kmsConfig.getEndPoint()).orElse("").getBytes(StandardCharsets.UTF_8);
            this.keyProvider = KeyProviderEnum.KMS_PROVIDER.getName().getBytes(StandardCharsets.UTF_8);
            this.keyProviderLength = keyProvider.length;
            this.discovery = Discovery.DISCOVERY;
            this.keyInformation = buildKeyInformation(Discovery.DISCOVERY);
            this.keyInformationLength = keyInformation.length;
        }

        /**
         * 总长度包括各类信息数组的长度和长度数字对应的字节数，
         * 如datakey数组和dataKeyLength对应的short数字的转换成的字节数组
         * 用于反序列化时，根据dataKeyLength确定dataKey的数组长度
         * 其中dataKeyLength为short，占2个字节，keyInformationLength和keyProviderLength
         * 为byte，占一个字节，固需要在最后加4个byte长度
         */
        this.totalLength = dataKeyLength + keyProviderLength + keyInformationLength + 4;
    }

    public byte[] getDataKey() {
        return dataKey;
    }

    public String getKeyId() {
        return Utils.byteToString(keyId);
    }

    public String getRegion() {
        return Utils.byteToString(region);
    }

    public String getProjectId() {
        return Utils.byteToString(projectId);
    }

    public String getEndPoint() {
        return Utils.byteToString(endPoint);
    }

    private byte[] buildKeyInformation(Discovery discovery) {
        ByteBuffer buffer = ByteBuffer.allocate(Short.MAX_VALUE);
        buffer.put(discovery.getCode());
        if (discovery.isDiscovery) {
            buffer.put((byte) keyId.length);
            buffer.put(keyId);
            buffer.put((byte) region.length);
            buffer.put(region);
            buffer.put((byte) projectId.length);
            buffer.put(projectId);
            buffer.put((byte) endPoint.length);
            buffer.put(endPoint);
        }
        buffer.flip();
        byte[] keyInformations = new byte[buffer.limit()];
        buffer.get(keyInformations);
        return keyInformations;
    }

    public byte[] toByteArray() {
        ByteBuffer buffer = ByteBuffer.allocate(this.totalLength);
        buffer.put((byte) keyProviderLength);
        buffer.put(keyProvider);
        buffer.put((byte) keyInformationLength);
        buffer.put(keyInformation);
        buffer.putShort(dataKeyLength);
        buffer.put(dataKey);
        return buffer.array();
    }

    public void byteArrayToBean(DataInputStream dataStream) throws IOException {
        keyProviderLength = dataStream.readByte() & 0xFF;
        this.keyProvider = new byte[keyProviderLength];
        int read = dataStream.read(keyProvider);
        if (read != keyProvider.length) {
            throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
        }
        keyInformationLength = dataStream.readByte() & 0xFF;
        if (keyInformationLength > 0) {
            this.keyInformation = new byte[keyInformationLength];
            int readKeyInfo = dataStream.read(keyInformation);
            if (readKeyInfo != keyInformation.length) {
                throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
            }
            parseKeyInformation();
        }
        dataKeyLength = dataStream.readShort();
        this.dataKey = new byte[dataKeyLength];
        int readDataKey = dataStream.read(dataKey);
        if (readDataKey != dataKey.length) {
            throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
        }
        this.totalLength = dataKeyLength + keyProviderLength + keyInformationLength + 4;
    }

    private void parseKeyInformation() {
        try (ByteArrayInputStream outBytes = new ByteArrayInputStream(keyInformation);
            DataInputStream dataStream = new DataInputStream(outBytes)) {
            byte code = dataStream.readByte();
            if (Discovery.getDiscoveryStatus(code)) {
                keyId = readField(dataStream);
                region = readField(dataStream);
                projectId = readField(dataStream);
                endPoint = readField(dataStream);
                discovery = Discovery.DISCOVERY;
            } else {
                discovery = Discovery.DISCOVERY;
            }
        } catch (IOException e) {
            throw new HuaweicloudException(e);
        }

    }

    private byte[] readField(DataInputStream dataStream) throws IOException {
        int len = dataStream.readByte() & 0xFF;
        byte[] bytes = new byte[len];
        int read = dataStream.read(bytes);
        if (read != bytes.length) {
            throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
        }
        return bytes;
    }

    enum Discovery {
        DISCOVERY(true, (byte) 1),
        NO_DISCOVERY(false, (byte) 2);

        boolean isDiscovery;

        byte code;

        Discovery(boolean isDiscovery, byte code) {
            this.isDiscovery = isDiscovery;
            this.code = code;
        }

        public static boolean getDiscoveryStatus(byte code) {
            for (Discovery discovery : Discovery.values()) {
                if (code == discovery.getCode()) {
                    return discovery.isDiscovery;
                }
            }
            return false;
        }

        public boolean isDiscovery() {
            return isDiscovery;
        }

        public byte getCode() {
            return code;
        }
    }

}

