package com.huawei.encyptionsdk.test.keyringtest;

import com.huaweicloud.encryptionsdk.common.FilePathForExampleConstants;
import com.huaweicloud.encryptionsdk.common.Utils;
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

/**
 * @author zc
 * @ClassName RawAesKeyringTest
 * @description:
 * @datetime 2022年 09月 08日 16:23
 */
public class RawSm2KeyringTest {
    @Test
    public void Should_ok_When_StateUnderSM2EncryptTest()
        throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
        BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidCipherTextException {
        RawKeyringFactory rawKeyringFactory = new RawKeyringFactory();
        RawKeyring sm2 = rawKeyringFactory.getKeyring("sm2");
        String dataKey = "5sFKOkwE2lRAIASXm3QFNoNRX1GbEKYgVZHmOdi7smU=";
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        dataKeyMaterials.setCryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING);
        byte[] decode = Base64.getDecoder().decode(dataKey);
        dataKeyMaterials.setPlaintextDataKey(new SecretKeySpec(decode, 0, decode.length, "AES"));
        sm2.setPrivateKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.PRI_FILE_PATH)));
        sm2.setPublicKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.PUB_FILE_PATH)));
        sm2.encryptDataKey(dataKeyMaterials);
        dataKeyMaterials.setPlaintextDataKey(null);
        sm2.decryptDataKey(dataKeyMaterials);
        SecretKey plaintextDataKey = dataKeyMaterials.getPlaintextDataKey();
        String encodedKey = Base64.getEncoder().encodeToString(plaintextDataKey.getEncoded());
        Assert.assertEquals(encodedKey, dataKey);

    }
}
