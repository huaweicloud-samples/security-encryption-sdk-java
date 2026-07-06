package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.CipherTamperedException;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.handler.CipherHandler;
import com.huaweicloud.encryptionsdk.model.CipherHeader;
import com.huaweicloud.encryptionsdk.model.CiphertextDataKey;
import com.huaweicloud.encryptionsdk.model.KeyCapsule;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class CipherHeaderTest {

    private static final String DATA_KEY = "5sFKOkwE2lRAIASXm3QFNoNRX1GbEKYgVZHmOdi7smU=";
    private static final byte[] CDK_BYTES = {1, 2, 3, 2, 3, 5, 6, 3, 2, 1, 2, 3, 2, 3, 5};

    private static SecretKey defaultSecretKey() {
        return Utils.byteToSecretKey(Base64.getDecoder().decode(DATA_KEY), "AES");
    }

    private static HashMap<String, String> defaultContext() {
        HashMap<String, String> map = new HashMap<>();
        map.put("dsfa", "dfsf");
        return map;
    }

    private static ArrayList<CiphertextDataKey> defaultCdkList() {
        ArrayList<CiphertextDataKey> list = new ArrayList<>();
        list.add(new CiphertextDataKey(CDK_BYTES));
        return list;
    }

    private static CipherHeader buildV1Header(CryptoAlgorithm alg, SecretKey key) throws Exception {
        return new CipherHeader(alg, defaultContext(), defaultCdkList(), key);
    }

    private static CipherHeader buildV2Header(CryptoAlgorithm alg, SecretKey key, KeyCapsule capsule) throws Exception {
        return new CipherHeader(alg, defaultContext(), defaultCdkList(), key, capsule);
    }

    private static byte[] buildFullSerialized(CipherHeader header) throws Exception {
        byte[] authFields = header.serializeAuthenticatedFields();
        byte[] headerTag = header.getHeaderTag();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (DataOutputStream dos = new DataOutputStream(baos)) {
            dos.write(authFields);
            dos.writeShort(headerTag.length);
            dos.write(headerTag);
            dos.flush();
        }
        return baos.toByteArray();
    }

    private static CipherHeader deserializeFrom(byte[] data) throws Exception {
        try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data))) {
            CipherHeader header = new CipherHeader();
            header.deserializeAuthenticatedFields(dis);
            return header;
        }
    }

    @Test
    public void Should_ok_When_CipherHeaderVerifyTest() throws Exception {
        SecretKey secretKey = defaultSecretKey();
        CipherHeader cipherHeader = buildV1Header(CryptoAlgorithm.AES_256_GCM_NOPADDING, secretKey);
        CipherHandler cipherHandler = new CipherHandler(CryptoAlgorithm.AES_256_GCM_NOPADDING, secretKey, Cipher.ENCRYPT_MODE);
        cipherHeader.verifyHeader(cipherHandler);
        assertNotNull(cipherHeader.getHeaderTag());
    }

    @Test
    public void testV2HeaderWithKeyCapsule() throws Exception {
        SecretKey secretKey = defaultSecretKey();
        KeyCapsule keyCapsule = KeyCapsule.builder().keyId("key-123").datakeyCapsule("capsuledata").accessPointType(2).build();
        CipherHeader cipherHeader = buildV2Header(CryptoAlgorithm.AES_256_GCM_NOPADDING, secretKey, keyCapsule);
        CipherHandler cipherHandler = new CipherHandler(CryptoAlgorithm.AES_256_GCM_NOPADDING, secretKey, Cipher.ENCRYPT_MODE);
        cipherHeader.verifyHeader(cipherHandler);
        assertNotNull(cipherHeader.getHeaderTag());
        assertNotNull(cipherHeader.getKeyCapsule());
    }

    @Test
    public void testV1HeaderSerializeOnly() throws Exception {
        SecretKey secretKey = defaultSecretKey();
        CipherHeader cipherHeader = buildV1Header(CryptoAlgorithm.AES_256_GCM_NOPADDING, secretKey);
        assertNotNull(cipherHeader.serializeAuthenticatedFields());
    }

    @Test
    public void testV2HeaderSerializeAndDeserialize() throws Exception {
        SecretKey secretKey = defaultSecretKey();
        KeyCapsule keyCapsule = KeyCapsule.builder().keyId("key-123").datakeyCapsule("capsuledata").accessPointType(2).build();
        CipherHeader cipherHeader = buildV2Header(CryptoAlgorithm.AES_256_GCM_NOPADDING, secretKey, keyCapsule);
        CipherHeader deserialized = deserializeFrom(buildFullSerialized(cipherHeader));
        assertEquals(CryptoAlgorithm.AES_256_GCM_NOPADDING, deserialized.getAlgorithm());
        assertNotNull(deserialized.getEncryptionContext());
        assertEquals(1, deserialized.getCiphertextDataKeys().size());
        assertNotNull(deserialized.getKeyCapsule());
        assertEquals("key-123", deserialized.getKeyCapsule().getKeyId());
        assertEquals("capsuledata", deserialized.getKeyCapsule().getDatakeyCapsule());
        assertEquals(2, deserialized.getKeyCapsule().getAccessPointType());
    }

    @Test
    public void testV1HeaderSerializeAndDeserialize() throws Exception {
        SecretKey secretKey = defaultSecretKey();
        CipherHeader cipherHeader = buildV1Header(CryptoAlgorithm.AES_256_GCM_NOPADDING, secretKey);
        CipherHeader deserialized = deserializeFrom(buildFullSerialized(cipherHeader));
        assertEquals(CryptoAlgorithm.AES_256_GCM_NOPADDING, deserialized.getAlgorithm());
        assertNotNull(deserialized.getEncryptionContext());
        assertEquals(1, deserialized.getCiphertextDataKeys().size());
        assertNull(deserialized.getKeyCapsule());
    }

    @Test
    public void testSM4CBCHeaderVerify() throws Exception {
        SecretKey secretKey = defaultSecretKey();
        CipherHeader cipherHeader = buildV1Header(CryptoAlgorithm.SM4_128_CBC_PADDING, secretKey);
        CipherHandler cipherHandler = new CipherHandler(CryptoAlgorithm.SM4_128_CBC_PADDING, secretKey, Cipher.ENCRYPT_MODE);
        cipherHeader.verifyHeader(cipherHandler);
        assertNotNull(cipherHeader.getHeaderTag());
    }

    @Test
    public void testSerializeAndDeserializeFileFields() throws Exception {
        SecretKey secretKey = defaultSecretKey();
        CipherHeader cipherHeader = buildV1Header(CryptoAlgorithm.AES_256_GCM_NOPADDING, secretKey);
        cipherHeader.setIv(new byte[12]);
        cipherHeader.setContentLength(100);
        byte[] fileFields = cipherHeader.serializeFileFields();
        assertNotNull(fileFields);

        CipherHeader deserialized = new CipherHeader();
        deserialized.deserializeFileFields(fileFields, CryptoAlgorithm.AES_256_GCM_NOPADDING);
        assertEquals(100, deserialized.getContentLength());
    }

    @Test
    public void testGetFileHeaderLength() {
        int len = new CipherHeader().getFileHeaderLength(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        assertEquals(CryptoAlgorithm.AES_256_GCM_NOPADDING.getIvLen() + 8, len);
    }

    @Test
    public void testDefaultConstructor() {
        assertNotNull(new CipherHeader());
    }

    @Test(expected = HuaweicloudException.class)
    public void testDeserializeUnsupportedVersion() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (DataOutputStream dos = new DataOutputStream(baos)) {
            dos.writeByte(0);
            dos.flush();
        }
        try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
            new CipherHeader().deserializeAuthenticatedFields(dis);
        }
    }

    @Test
    public void testV2DeserializeWithZeroKeyCapsuleLength() throws Exception {
        SecretKey secretKey = defaultSecretKey();
        HashMap<String, String> map = defaultContext();
        ArrayList<CiphertextDataKey> list = defaultCdkList();
        byte[] dummyTag = new byte[16];

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (DataOutputStream dos = new DataOutputStream(baos)) {
            dos.writeByte(2);
            dos.writeShort(CryptoAlgorithm.AES_256_GCM_NOPADDING.getValue());
            byte[] ctxBytes = Utils.serializeContext(map);
            dos.writeShort(ctxBytes.length);
            dos.write(ctxBytes);
            dos.writeByte(1);
            for (CiphertextDataKey dk : list) {
                dos.write(dk.toByteArray());
            }
            dos.writeByte(1);
            dos.writeByte(CryptoAlgorithm.AES_256_GCM_NOPADDING.getIvLen());
            dos.writeInt(0);
            dos.writeShort(dummyTag.length);
            dos.write(dummyTag);
            dos.flush();
        }

        try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
            CipherHeader deserialized = new CipherHeader();
            deserialized.deserializeAuthenticatedFields(dis);
            assertEquals(CryptoAlgorithm.AES_256_GCM_NOPADDING, deserialized.getAlgorithm());
            assertNull(deserialized.getKeyCapsule());
        }
    }

    @Test(expected = CipherTamperedException.class)
    public void testSM4CBCTamperedHeader() throws Exception {
        SecretKey secretKey = defaultSecretKey();
        CipherHeader cipherHeader = buildV1Header(CryptoAlgorithm.SM4_128_CBC_PADDING, secretKey);
        java.lang.reflect.Field headerTagField = CipherHeader.class.getDeclaredField("headerTag");
        headerTagField.setAccessible(true);
        byte[] originalTag = (byte[]) headerTagField.get(cipherHeader);
        byte[] tamperedTag = new byte[originalTag.length];
        tamperedTag[0] = (byte) (originalTag[0] + 1);
        headerTagField.set(cipherHeader, tamperedTag);
        CipherHandler cipherHandler = new CipherHandler(CryptoAlgorithm.SM4_128_CBC_PADDING, secretKey, Cipher.ENCRYPT_MODE);
        cipherHeader.verifyHeader(cipherHandler);
    }

    @Test
    public void testV1DeserializeWithEmptyContext() throws Exception {
        SecretKey secretKey = defaultSecretKey();
        CipherHeader cipherHeader = buildV1Header(CryptoAlgorithm.AES_256_GCM_NOPADDING, secretKey);
        CipherHeader deserialized = deserializeFrom(buildFullSerialized(cipherHeader));
        assertNotNull(deserialized.getEncryptionContext());
    }

    @Test
    public void testSetters() {
        CipherHeader header = new CipherHeader();
        header.setAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        assertEquals(CryptoAlgorithm.AES_256_GCM_NOPADDING, header.getAlgorithm());

        HashMap<String, String> ctx = new HashMap<>();
        ctx.put("key", "value");
        header.setEncryptionContext(ctx);
        assertEquals(ctx, header.getEncryptionContext());

        ArrayList<CiphertextDataKey> keys = new ArrayList<>();
        header.setCiphertextDataKeys(keys);
        assertEquals(keys, header.getCiphertextDataKeys());

        KeyCapsule capsule = KeyCapsule.builder().keyId("kid").datakeyCapsule("dc").accessPointType(1).build();
        header.setKeyCapsule(capsule);
        assertEquals(capsule, header.getKeyCapsule());
    }

    @Test
    public void testV2HeaderWithNullKeyCapsuleFields() throws Exception {
        SecretKey secretKey = defaultSecretKey();
        KeyCapsule keyCapsule = KeyCapsule.builder().keyId(null).datakeyCapsule(null).accessPointType(2).build();
        CipherHeader cipherHeader = buildV2Header(CryptoAlgorithm.AES_256_GCM_NOPADDING, secretKey, keyCapsule);
        CipherHeader deserialized = deserializeFrom(buildFullSerialized(cipherHeader));
        assertEquals(CryptoAlgorithm.AES_256_GCM_NOPADDING, deserialized.getAlgorithm());
        assertNotNull(deserialized.getKeyCapsule());
        assertNull(deserialized.getKeyCapsule().getKeyId());
        assertNull(deserialized.getKeyCapsule().getDatakeyCapsule());
    }
}
