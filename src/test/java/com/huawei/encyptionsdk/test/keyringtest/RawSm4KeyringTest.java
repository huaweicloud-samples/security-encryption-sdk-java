package com.huawei.encyptionsdk.test.keyringtest;

import com.huaweicloud.encryptionsdk.common.FilePathForExampleConstants;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.KeyringNotMatchException;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.model.CiphertextDataKey;
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
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

public class RawSm4KeyringTest {
    @Test
    public void Should_ok_When_StateUnderSM4EncryptTest()
        throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
        BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        String dataKey = "5sFKOkwE2lRAIASXm3QFNoNRX1GbEKYgVZHmOdi7smU=";
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        byte[] decode = Base64.getDecoder().decode(dataKey);
        dataKeyMaterials.setPlaintextDataKey(new SecretKeySpec(decode, 0, decode.length, "SM4"));
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring keyring = rawKeyringFactory.getKeyring("sm4_gcm");
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_128_FILE_PATH)));
        dataKeyMaterials.setCryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING);
        keyring.encryptDataKey(dataKeyMaterials);
        dataKeyMaterials.setPlaintextDataKey(null);
        keyring.decryptDataKey(dataKeyMaterials);
        SecretKey plaintextDataKey = dataKeyMaterials.getPlaintextDataKey();
        String encodedKey = Base64.getEncoder().encodeToString(plaintextDataKey.getEncoded());
        Assert.assertEquals(dataKey, encodedKey);
    }

    @Test
    public void Should_ok_When_StateUnderSM4CBCEncryptTest()
        throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
        BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        String dataKey = "5sFKOkwE2lRAIASXm3QFNoNRX1GbEKYgVZHmOdi7smU=";
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        byte[] decode = Base64.getDecoder().decode(dataKey);
        dataKeyMaterials.setPlaintextDataKey(new SecretKeySpec(decode, 0, decode.length, "SM4"));
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring keyring = rawKeyringFactory.getKeyring("sm4_cbc");
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_128_FILE_PATH)));
        dataKeyMaterials.setCryptoAlgorithm(CryptoAlgorithm.SM4_128_CBC_PADDING);
        keyring.encryptDataKey(dataKeyMaterials);
        dataKeyMaterials.setPlaintextDataKey(null);
        keyring.decryptDataKey(dataKeyMaterials);
        SecretKey plaintextDataKey = dataKeyMaterials.getPlaintextDataKey();
        String encodedKey = Base64.getEncoder().encodeToString(plaintextDataKey.getEncoded());
        Assert.assertEquals(encodedKey, dataKey);
    }

    @Test
    public void testSM4CBCDecryptWithShortDataKey() throws IOException {
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring keyring = rawKeyringFactory.getKeyring("sm4_cbc");
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_128_FILE_PATH)));

        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        dataKeyMaterials.setCryptoAlgorithm(CryptoAlgorithm.SM4_128_CBC_PADDING);
        byte[] decode = Base64.getDecoder().decode("5sFKOkwE2lRAIASXm3QFNoNRX1GbEKYgVZHmOdi7smU=");
        dataKeyMaterials.setPlaintextDataKey(new SecretKeySpec(decode, 0, decode.length, "SM4"));

        List<CiphertextDataKey> shortKeys = new ArrayList<>();
        shortKeys.add(new CiphertextDataKey(new byte[]{1, 2, 3}));
        dataKeyMaterials.setCiphertextDataKeys(shortKeys);

        try {
            keyring.decryptDataKey(dataKeyMaterials);
        } catch (KeyringNotMatchException e) {
            Assert.assertNotNull(e);
        }
    }

    @Test
    public void testSM4GCMDecryptWithShortDataKey() throws IOException {
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring keyring = rawKeyringFactory.getKeyring("sm4_gcm");
        keyring.setSymmetricKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.BIT_128_FILE_PATH)));

        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        dataKeyMaterials.setCryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING);
        byte[] decode = Base64.getDecoder().decode("5sFKOkwE2lRAIASXm3QFNoNRX1GbEKYgVZHmOdi7smU=");
        dataKeyMaterials.setPlaintextDataKey(new SecretKeySpec(decode, 0, decode.length, "SM4"));

        List<CiphertextDataKey> shortKeys = new ArrayList<>();
        shortKeys.add(new CiphertextDataKey(new byte[]{1, 2, 3}));
        dataKeyMaterials.setCiphertextDataKeys(shortKeys);

        try {
            keyring.decryptDataKey(dataKeyMaterials);
        } catch (KeyringNotMatchException e) {
            Assert.assertNotNull(e);
        }
    }
}
