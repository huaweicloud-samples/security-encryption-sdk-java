package com.huawei.encyptionsdk.test.keyringtest;

import com.huaweicloud.encryptionsdk.common.FilePathForExampleConstants;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.KeyringNotMatchException;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

public class RawRSAKeyringTest {
    @Test
    public void Should_ok_When_StateUnderRSAEncryptTest()
        throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
        BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring sm2 = rawKeyringFactory.getKeyring("rsa");
        String dataKey = "5sFKOkwE2lRAIASXm3QFNoNRX1GbEKYgVZHmOdi7smU=";
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        dataKeyMaterials.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        byte[] decode = Base64.getDecoder().decode(dataKey);
        dataKeyMaterials.setPlaintextDataKey(new SecretKeySpec(decode, 0, decode.length, "AES"));
        sm2.setPrivateKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PRI_FILE_PATH)));
        sm2.setPublicKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PUB_FILE_PATH)));
        sm2.encryptDataKey(dataKeyMaterials);
        dataKeyMaterials.setPlaintextDataKey(null);
        sm2.decryptDataKey(dataKeyMaterials);
        SecretKey plaintextDataKey = dataKeyMaterials.getPlaintextDataKey();
        String encodedKey = Base64.getEncoder().encodeToString(plaintextDataKey.getEncoded());
        Assert.assertEquals(encodedKey, dataKey);

    }

    @Test
    public void testRealDecryptWithWrongKey() throws IOException {
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring rsa = rawKeyringFactory.getKeyring("rsa");
        String dataKey = "5sFKOkwE2lRAIASXm3QFNoNRX1GbEKYgVZHmOdi7smU=";
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        dataKeyMaterials.setCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING);
        byte[] decode = Base64.getDecoder().decode(dataKey);
        dataKeyMaterials.setPlaintextDataKey(new SecretKeySpec(decode, 0, decode.length, "AES"));
        rsa.setPublicKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PUB_FILE_PATH)));
        rsa.encryptDataKey(dataKeyMaterials);

        rsa.setPrivateKey(new byte[][]{new byte[]{1, 2, 3}});
        dataKeyMaterials.setPlaintextDataKey(null);
        try {
            rsa.decryptDataKey(dataKeyMaterials);
        } catch (KeyringNotMatchException e) {
            Assert.assertNotNull(e);
        }
    }

    @Test
    public void testSetPrivateKeyList() throws IOException {
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring rsa = rawKeyringFactory.getKeyring("rsa");

        List<byte[]> keys = Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PRI_FILE_PATH));
        rsa.setPrivateKey(keys);
        Assert.assertEquals(1, rsa.getPrivateKey().size());
    }

    @Test
    public void testSetPublicKeyList() throws IOException {
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring rsa = rawKeyringFactory.getKeyring("rsa");

        List<byte[]> keys = Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PUB_FILE_PATH));
        rsa.setPublicKey(keys);
        Assert.assertEquals(1, rsa.getPublicKey().size());
    }

    @Test
    public void testSetSymmetricKey() {
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring rsa = rawKeyringFactory.getKeyring("rsa");

        rsa.setSymmetricKey(new byte[]{1, 2, 3});
        Assert.assertEquals(1, rsa.getSymmetricKey().size());

        rsa.setSymmetricKey(Collections.singletonList(new byte[]{4, 5, 6}));
        Assert.assertEquals(2, rsa.getSymmetricKey().size());
    }

    @Test
    public void testGetEncryptSecretKey() throws IOException {
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring rsa = rawKeyringFactory.getKeyring("rsa");

        rsa.setPublicKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PUB_FILE_PATH)));
        List<byte[]> encKeys = rsa.getEncryptSecretKey();
        Assert.assertEquals(1, encKeys.size());
    }

    @Test
    public void testGetDecryptSecretKey() throws IOException {
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring rsa = rawKeyringFactory.getKeyring("rsa");

        rsa.setPrivateKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PRI_FILE_PATH)));
        List<byte[]> decKeys = rsa.getDecryptSecretKey();
        Assert.assertEquals(1, decKeys.size());
    }
}
