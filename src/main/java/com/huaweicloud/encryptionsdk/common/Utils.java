package com.huaweicloud.encryptionsdk.common;

import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.exception.KeyParseException;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.KeyCapsuleConfig;
import com.huaweicloud.sdk.core.utils.StringUtils;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * common utils
 */
public class Utils {

    public static <T> boolean isEmpty(T t) {
        if (t == null) {
            return true;
        }
        if (t instanceof String) {
            return "".equals(t);
        }
        if (t instanceof List) {
            return ((List<?>) t).size() <= 0;
        }
        return true;
    }

    public static List<byte[]> readMasterKey(List<String> keyPath) {
        List<byte[]> publicKeyList = new ArrayList<>();
        for (String path : keyPath) {
            File file = new File(path);
            if (!file.exists()) {
                throw new HuaweicloudException("file not exists:" + file.getName());
            }
            try (InputStream inputStream = Files.newInputStream(file.toPath());) {
                int available = inputStream.available();
                byte[] bytes = new byte[available];
                int read = inputStream.read(bytes);
                if (read != bytes.length) {
                    throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
                }
                byte[] removeLineSymbol = removeLineSymbol(bytes);
                byte[] originalMasterKey = Base64.getDecoder().decode(removeLineSymbol);
                publicKeyList.add(originalMasterKey);
            } catch (IOException e) {
                throw new HuaweicloudException(e);
            }
        }
        return publicKeyList;
    }

    public static byte[] longToByte(long num) {
        return ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(num).array();
    }

    public static long byteToLong(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.put(bytes, 0, bytes.length);
        buffer.flip();
        return buffer.getLong();
    }

    public static int byteToInt(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.put(bytes, 0, bytes.length);
        buffer.flip();
        return buffer.getInt();
    }

    public static long addPreventOverFlow(long a, long b) {
        long r = a + b;
        if (a > 0 && b > 0 && r < a) {
            return Long.MAX_VALUE;
        }
        if (a < 0 && b < 0 && r > a) {
            return Long.MIN_VALUE;
        }
        return r;
    }

    public static byte[] commonHash(byte[] data, String alg) {
        byte[] digest = null;
        try {
            MessageDigest md = CryptoFactory.getMessageDigest(alg);
            md.update(data);
            digest = md.digest();
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.MESSAGE_DIGEST_ERROR.getMessage());
        }
        return digest;
    }

    public static String byteToString(byte[] bytes) {
        return new String(Optional.ofNullable(bytes).orElse(new byte[0]));
    }

    public static byte[] removeLineSymbol(byte[] bytes) {
        String str = new String(bytes, StandardCharsets.UTF_8).replaceAll("(\\r\\n|\\n|\\\\n)", "");
        return str.getBytes(StandardCharsets.UTF_8);
    }

    public static SecretKey byteToSecretKey(byte[] bytes, String algorithm) {
        SecretKey originalKey = new SecretKeySpec(bytes, 0, bytes.length, algorithm);
        return originalKey;
    }

    public static PublicKey getPublicKey(byte[] publicKey, String algFlag) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
            KeyFactory keyFactory = CryptoFactory.getKeyFactory(algFlag);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new KeyParseException(ErrorMessage.PUBLIC_KEY_PARSE_EXCEPTION.getMessage(), e);
        }
    }

    public static PrivateKey getPrivateKey(byte[] privateKey, String algFlag) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
            KeyFactory keyFactory = CryptoFactory.getKeyFactory(algFlag);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new KeyParseException(ErrorMessage.PRIVATE_KEY_PARSE_EXCEPTION.getMessage(), e);
        }
    }

    public static byte[] serializeContext(Map<String, String> encryptionContext) {
        if (encryptionContext == null || encryptionContext.size() == 0) {
            return new byte[0];
        }
        List<Map.Entry<String, String>> list = new ArrayList<>(encryptionContext.entrySet());
        Collections.sort(list, Comparator.comparing(Map.Entry::getValue));
        ByteBuffer buffer = ByteBuffer.allocate(Short.MAX_VALUE);
        buffer.putShort((short) encryptionContext.size());
        for (Map.Entry<String, String> entry : list) {
            byte[] keyBytes = entry.getKey().getBytes(StandardCharsets.UTF_8);
            buffer.putShort((short) keyBytes.length);
            buffer.put(keyBytes);
            byte[] valueBytes = entry.getValue().getBytes(StandardCharsets.UTF_8);
            buffer.putShort((short) valueBytes.length);
            buffer.put(valueBytes);
        }
        buffer.flip();
        byte[] encryptionContextBytes = new byte[buffer.limit()];
        buffer.get(encryptionContextBytes);
        return encryptionContextBytes;
    }

    public static Map<String, String> deserializeContext(byte[] encryptionContextBytes) {
        if (encryptionContextBytes == null || encryptionContextBytes.length == 0) {
            return new HashMap<>();
        }
        ByteBuffer buffer = ByteBuffer.allocate(encryptionContextBytes.length);
        buffer.put(encryptionContextBytes);
        buffer.flip();
        Map<String, String> map = new HashMap<>();
        int encryptionContextSize = buffer.getShort();
        for (int i = 0; i < encryptionContextSize; i++) {
            int keyLen = buffer.getShort();
            byte[] keyBytes = new byte[keyLen];
            buffer.get(keyBytes);
            int valueLen = buffer.getShort();
            byte[] valueBytes = new byte[valueLen];
            buffer.get(valueBytes);
            map.put(new String(keyBytes, StandardCharsets.UTF_8), new String(valueBytes, StandardCharsets.UTF_8));
        }
        return map;
    }

    public static byte[] hexToBytes(String hexString) throws DecoderException {
        // 128字节的常量数组，非16进制的
        final byte[] btHEX = {
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, '0', '1', '2', '3', '4',
            '5', '6', '7', '8', '9', -1, -1, -1, -1, -1, -1, -1, 'A', 'B', 'C', 'D', 'E', 'F', -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 'a', 'b', 'c', 'd', 'e',
            'f', -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
        };

        final int length2 = 2;

        if (StringUtils.isEmpty(hexString) || hexString.length() % length2 != 0) {
            throw new DecoderException("invalid string length.");
        }

        for (int i = 0; i < hexString.length(); i++) {
            if (btHEX[hexString.charAt(i)] < 0) {
                throw new DecoderException("invalid string char. " + hexString.charAt(i));
            }
        }

        return Hex.decodeHex(hexString.toCharArray());
    }

    public static String bytesToHex(byte[] bytes) {
        return new String(Hex.encodeHex(bytes));
    }

    public static KMSConfig getCapsuleKMSConfig(List<KMSConfig> kmsConfigList, KeyCapsuleConfig keyCapsuleConfig) {
        if (Utils.isEmpty(kmsConfigList)) {
            throw new HuaweicloudException(ErrorMessage.CONFIG_NULL_ERROR.getMessage());
        }
        if (keyCapsuleConfig == null) {
            throw new HuaweicloudException("KeyCapsuleConfig is required for key capsule mode");
        }
        KMSConfig kmsConfig = null;
        for (KMSConfig tempConfig : kmsConfigList) {
            if (tempConfig.getRegion().equalsIgnoreCase(keyCapsuleConfig.getRegion())) {
                kmsConfig = tempConfig;
                break;
            }
        }
        if (kmsConfig == null) {
            throw new HuaweicloudException(ErrorMessage.KEY_CAPSULE_REGION_NOT_FOUND.getMessage() + keyCapsuleConfig.getRegion());
        }
        return kmsConfig;
    }
}
