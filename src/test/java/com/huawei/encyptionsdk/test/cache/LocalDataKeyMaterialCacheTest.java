package com.huawei.encyptionsdk.test.cache;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.cache.DataKeyCache;
import com.huaweicloud.encryptionsdk.cache.LocalDataKeyCache;
import com.huaweicloud.encryptionsdk.common.FilePathForExampleConstants;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.keyrings.Keyring;
import com.huaweicloud.encryptionsdk.keyrings.RawKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.meterialmanager.CryptoMeterialManager;
import com.huaweicloud.encryptionsdk.meterialmanager.DefaultCryptoMeterialsManager;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;
import org.apache.commons.codec.DecoderException;
import org.junit.Before;
import org.junit.Test;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class LocalDataKeyMaterialCacheTest {
    private final static DataKeyCache.UsageStatus ZERO_USAGE_INFO = new DataKeyCache.UsageStatus(0, 0);

    LocalDataKeyCache cache;

    Long survivalTime = 1000L;

    private static final String ENTRY_KEY0 = UUID.randomUUID().toString();

    private static final String ENTRY_KEY1 = UUID.randomUUID().toString();

    private static final String ENTRY_KEY2 = UUID.randomUUID().toString();

    private static final String ENTRY_KEY3 = UUID.randomUUID().toString();

    private static final String ENTRY_KEY4 = UUID.randomUUID().toString();

    private static final String ENTRY_KEY5 = UUID.randomUUID().toString();

    private static final List<String> ENTRY_KEY_LIST = Arrays.asList(ENTRY_KEY0, ENTRY_KEY1, ENTRY_KEY2, ENTRY_KEY3,
        ENTRY_KEY4, ENTRY_KEY5);

    private CryptoMeterialManager cryptoMeterialManager;

    private Keyring keyring;

    private DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();

    private Map<String, String> encryptionContext = new HashMap<>();

    @Before
    public void setUp() throws FileNotFoundException {
        cache = new LocalDataKeyCache();
        cache.setCapacity(20);
        cache.setSurvivalTime(5000);
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
            .cryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING)
            .build();
        RawKeyring tempKeyring = new RawKeyringFactory().getKeyring(KeyringTypeEnum.RAW_RSA.getType());
        tempKeyring.setPrivateKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PRI_FILE_PATH)));
        tempKeyring.setPublicKey(Utils.readMasterKey(Collections.singletonList(FilePathForExampleConstants.RSA_PUB_FILE_PATH)));
        this.keyring = tempKeyring;
        cryptoMeterialManager = new DefaultCryptoMeterialsManager(huaweiConfig);
        encryptionContext.put("encryption", "context");
        encryptionContext.put("simple", "test");
        encryptionContext.put("caching", "encrypt");
        dataKeyMaterials.setCryptoAlgorithm(CryptoAlgorithm.SM4_128_GCM_NOPADDING);
        dataKeyMaterials.setEncryptionContexts(encryptionContext);
    }

    @Test
    public void Should_ok_When_CacheNUllTest() {
        assertNull(cache.getEntryForDecrypt(ENTRY_KEY0));
        assertNull(cache.getEntryForEncrypt(ENTRY_KEY0, ZERO_USAGE_INFO));
    }

    @Test
    public void Should_ok_When_CacheNotExistTest()
        throws DecoderException, NoSuchAlgorithmException, IOException, ExecutionException, InterruptedException {
        List<DataKeyMaterials> list = new ArrayList<>();

        for (int i = 0; i < 6; i++) {
            list.add(cryptoMeterialManager.getMaterialsForEncrypt(keyring, dataKeyMaterials,
                "PLAIN_TEXT".getBytes(StandardCharsets.UTF_8).length));
        }
        cache.putEntryForDecrypt(ENTRY_KEY0, list.get(0));
        cache.putEntryForDecrypt(ENTRY_KEY1, list.get(1));
        cache.putEntryForDecrypt(ENTRY_KEY2, list.get(2));
        cache.putEntryForDecrypt(ENTRY_KEY3, list.get(3));
        cache.putEntryForDecrypt(ENTRY_KEY4, list.get(4));
        cache.putEntryForDecrypt(ENTRY_KEY5, list.get(5));
        DataKeyCache.DecryptCacheEntry entryForDecrypt = cache.getEntryForDecrypt("123456");
        assertNull(entryForDecrypt);
    }

    @Test
    public void Should_ok_When_CacheInvalidateTest()
        throws DecoderException, NoSuchAlgorithmException, IOException, ExecutionException, InterruptedException {
        List<DataKeyMaterials> list = new ArrayList<>();

        for (int i = 0; i < 6; i++) {
            DataKeyMaterials materialsForEncrypt = cryptoMeterialManager.getMaterialsForEncrypt(keyring,
                dataKeyMaterials, "PLAIN_TEXT".getBytes(StandardCharsets.UTF_8).length);
            list.add(materialsForEncrypt);
            cache.putEntryForEncrypt(ENTRY_KEY_LIST.get(i), materialsForEncrypt, new DataKeyCache.UsageStatus(1, 1));
        }
        cache.getEntryForEncrypt(ENTRY_KEY0, new DataKeyCache.UsageStatus(1, 1)).invalidate();
        assertNull(cache.getEntryForEncrypt(ENTRY_KEY0, new DataKeyCache.UsageStatus(1, 1)));
    }

    @Test
    public void Should_ok_When_CacheExistTest()
        throws DecoderException, NoSuchAlgorithmException, IOException, ExecutionException, InterruptedException {
        DataKeyMaterials dataKeyMaterials1 = cryptoMeterialManager.getMaterialsForEncrypt(keyring, dataKeyMaterials,
            "PLAIN_TEXT".getBytes(StandardCharsets.UTF_8).length);
        DataKeyMaterials dataKeyMaterials2 = cryptoMeterialManager.getMaterialsForEncrypt(keyring, dataKeyMaterials,
            "PLAIN_TEXT".getBytes(StandardCharsets.UTF_8).length);
        cache.putEntryForDecrypt(ENTRY_KEY0, dataKeyMaterials1);
        cache.putEntryForEncrypt(ENTRY_KEY1, dataKeyMaterials2, new DataKeyCache.UsageStatus(20, 2));
        assertEquals(dataKeyMaterials1, cache.getEntryForDecrypt(ENTRY_KEY0).getDataKeyMaterials());
        assertEquals(dataKeyMaterials2,
            cache.getEntryForEncrypt(ENTRY_KEY1, new DataKeyCache.UsageStatus(1, 1)).getDataKeyMaterials());
    }

    @Test
    public void Should_ok_When_CacheDecryptDefaultTTLTest()
        throws DecoderException, NoSuchAlgorithmException, IOException, InterruptedException, ExecutionException {
        List<DataKeyMaterials> list = new ArrayList<>();

        for (int i = 0; i < 6; i++) {
            list.add(cryptoMeterialManager.getMaterialsForEncrypt(keyring, dataKeyMaterials,
                "PLAIN_TEXT".getBytes(StandardCharsets.UTF_8).length));
        }
        cache.putEntryForDecrypt(ENTRY_KEY0, list.get(0));
        cache.putEntryForDecrypt(ENTRY_KEY1, list.get(1));
        cache.putEntryForDecrypt(ENTRY_KEY2, list.get(2));
        cache.putEntryForDecrypt(ENTRY_KEY3, list.get(3));
        cache.putEntryForDecrypt(ENTRY_KEY4, list.get(4));
        cache.putEntryForDecrypt(ENTRY_KEY5, list.get(5));
        assertEquals(list.get(0), cache.getEntryForDecrypt(ENTRY_KEY0).getDataKeyMaterials());
        Thread.sleep(6000);
        for (int i = 0; i < 6; i++) {
            assertNull(cache.getEntryForDecrypt(ENTRY_KEY_LIST.get(i)));
        }

    }

    @Test
    public void Should_ok_When_CacheEncryptDefaultTTLTest()
        throws DecoderException, NoSuchAlgorithmException, IOException, InterruptedException, ExecutionException {
        List<DataKeyMaterials> list = new ArrayList<>();

        for (int i = 0; i < 6; i++) {
            DataKeyMaterials materialsForEncrypt = cryptoMeterialManager.getMaterialsForEncrypt(keyring,
                dataKeyMaterials, "PLAIN_TEXT".getBytes(StandardCharsets.UTF_8).length);
            list.add(materialsForEncrypt);
            cache.putEntryForEncrypt(ENTRY_KEY_LIST.get(i), materialsForEncrypt, new DataKeyCache.UsageStatus(1, 1));
        }
        assertEquals(list.get(0),
            cache.getEntryForEncrypt(ENTRY_KEY0, new DataKeyCache.UsageStatus(1, 1)).getDataKeyMaterials());
        Thread.sleep(4000);
        assertEquals(list.get(1),
            cache.getEntryForEncrypt(ENTRY_KEY1, new DataKeyCache.UsageStatus(1, 1)).getDataKeyMaterials());
        Thread.sleep(2000);
        for (int i = 0; i < 6; i++) {
            assertNull(cache.getEntryForEncrypt(ENTRY_KEY_LIST.get(i), new DataKeyCache.UsageStatus(1, 1)));
        }

    }

    @Test
    public void Should_ok_When_CacheEncryptTTLTest()
        throws DecoderException, NoSuchAlgorithmException, IOException, InterruptedException, ExecutionException {
        List<DataKeyMaterials> list = new ArrayList<>();

        for (int i = 0; i < 6; i++) {
            DataKeyMaterials materialsForEncrypt = cryptoMeterialManager.getMaterialsForEncrypt(keyring,
                dataKeyMaterials, "PLAIN_TEXT".getBytes(StandardCharsets.UTF_8).length);
            list.add(materialsForEncrypt);
            cache.putEntryForEncrypt(ENTRY_KEY_LIST.get(i), 10000, materialsForEncrypt,
                new DataKeyCache.UsageStatus(1, 1));
        }
        assertEquals(list.get(0),
            cache.getEntryForEncrypt(ENTRY_KEY0, new DataKeyCache.UsageStatus(1, 1)).getDataKeyMaterials());
        Thread.sleep(4000);
        assertEquals(list.get(1),
            cache.getEntryForEncrypt(ENTRY_KEY1, new DataKeyCache.UsageStatus(1, 1)).getDataKeyMaterials());
        Thread.sleep(5000);
        for (int i = 0; i < 6; i++) {
            assertNotNull(cache.getEntryForEncrypt(ENTRY_KEY_LIST.get(i), new DataKeyCache.UsageStatus(1, 1))
                .getDataKeyMaterials());
        }

    }

    @Test
    public void Should_ok_When_CacheDecryptTTLTest()
        throws DecoderException, NoSuchAlgorithmException, IOException, InterruptedException, ExecutionException {
        List<DataKeyMaterials> list = new ArrayList<>();

        for (int i = 0; i < 6; i++) {
            DataKeyMaterials materialsForEncrypt = cryptoMeterialManager.getMaterialsForEncrypt(keyring,
                dataKeyMaterials, "PLAIN_TEXT".getBytes(StandardCharsets.UTF_8).length);
            list.add(materialsForEncrypt);
            cache.putEntryForDecrypt(ENTRY_KEY_LIST.get(i), 10000, materialsForEncrypt);
        }
        assertEquals(list.get(0), cache.getEntryForDecrypt(ENTRY_KEY0).getDataKeyMaterials());
        Thread.sleep(4000);
        assertEquals(list.get(1), cache.getEntryForDecrypt(ENTRY_KEY1).getDataKeyMaterials());
        Thread.sleep(5000);
        for (int i = 0; i < 6; i++) {
            assertNotNull(cache.getEntryForDecrypt(ENTRY_KEY_LIST.get(i)).getDataKeyMaterials());
        }

    }

    @Test
    public void Should_ok_When_CacheLimitTest()
        throws DecoderException, NoSuchAlgorithmException, IOException, InterruptedException, ExecutionException {

        List<DataKeyMaterials> list = new ArrayList<>();

        for (int i = 0; i < 6; i++) {
            DataKeyMaterials materialsForEncrypt = cryptoMeterialManager.getMaterialsForEncrypt(keyring,
                dataKeyMaterials, "PLAIN_TEXT".getBytes(StandardCharsets.UTF_8).length);
            list.add(materialsForEncrypt);
            cache.putEntryForDecrypt(ENTRY_KEY_LIST.get(i), 10000, materialsForEncrypt);
        }
        assertEquals(list.get(0), cache.getEntryForDecrypt(ENTRY_KEY0).getDataKeyMaterials());
        Thread.sleep(4000);
        assertEquals(list.get(1), cache.getEntryForDecrypt(ENTRY_KEY1).getDataKeyMaterials());
        Thread.sleep(5000);
        for (int i = 0; i < 6; i++) {
            assertNotNull(cache.getEntryForDecrypt(ENTRY_KEY_LIST.get(i)).getDataKeyMaterials());
        }

    }

}
