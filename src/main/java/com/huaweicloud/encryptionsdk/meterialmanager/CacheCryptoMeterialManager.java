package com.huaweicloud.encryptionsdk.meterialmanager;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.cache.DataKeyCache;
import com.huaweicloud.encryptionsdk.common.Constants;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.handler.DefaultSerializeHandler;
import com.huaweicloud.encryptionsdk.keyrings.Keyring;
import com.huaweicloud.encryptionsdk.model.CipherHeader;
import com.huaweicloud.encryptionsdk.model.CiphertextDataKey;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.DataMaterials;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import org.apache.commons.codec.DecoderException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.concurrent.ExecutionException;

/**
 * @description: 基于缓存的密钥管理器
 */
public class CacheCryptoMeterialManager implements CryptoMeterialManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(CacheCryptoMeterialManager.class);

    /**
     * cacheId摘要计算算法
     */
    private static final String CACHE_ID_ALGORITHM_SHA = "SHA-256";

    private static final String CACHE_ID_ALGORITHM_SM3 = "SM3";

    /**
     * 数据密钥最大加密数据条数
     */
    private static final long DEFAULT_MESSAGE_LIMIT = Integer.MAX_VALUE;

    /**
     * 数据密钥最大加密数据量
     */
    private static final long DEFAULT_BYTE_LIMIT = Long.MAX_VALUE;

    private long maxMessageLimit;

    private HuaweiConfig huaweiConfig;

    private long maxByteLimit;

    private final DataKeyCache cache;

    private CryptoMeterialManager cryptoMeterialManager;

    public CacheCryptoMeterialManager(DataKeyCache cache, HuaweiConfig huaweiConfig) {
        this.cache = cache;
        this.maxByteLimit = DEFAULT_BYTE_LIMIT;
        this.maxMessageLimit = DEFAULT_MESSAGE_LIMIT;
        this.huaweiConfig = huaweiConfig;
        this.cryptoMeterialManager = new DefaultCryptoMeterialsManager(huaweiConfig);
    }

    public long getMaxByteLimit() {
        return maxByteLimit;
    }

    public CacheCryptoMeterialManager setSurvivalTime(long survivalTime) {
        if (survivalTime <= 0) {
            throw new HuaweicloudException(ErrorMessage.CACHE_PARAM_LESS_THAN_ZERO.getMessage());
        }
        cache.setSurvivalTime(survivalTime);
        return this;
    }

    public CacheCryptoMeterialManager setMaxMessageLimit(long maxMessageLimit) {
        if (maxMessageLimit <= 0) {
            throw new HuaweicloudException(ErrorMessage.CACHE_PARAM_LESS_THAN_ZERO.getMessage());
        }
        this.maxMessageLimit = maxMessageLimit;
        return this;
    }

    public CacheCryptoMeterialManager setMaxByteLimit(long maxByteLimit) {
        if (maxByteLimit <= 0) {
            throw new HuaweicloudException(ErrorMessage.CACHE_PARAM_LESS_THAN_ZERO.getMessage());
        }
        this.maxByteLimit = maxByteLimit;
        return this;
    }

    @Override
    public DataKeyMaterials getMaterialsForEncrypt(Keyring keyring, DataKeyMaterials dataKeyMaterials,
        long plaintTextLength)
        throws NoSuchAlgorithmException, DecoderException, IOException, ExecutionException, InterruptedException {
        String cacheId = getCacheId(dataKeyMaterials);
        DataKeyCache.UsageStatus usageStatus = new DataKeyCache.UsageStatus(plaintTextLength, Constants.NUM_1);
        DataKeyCache.EncryptCacheEntry entryForEncrypt = cache.getEntryForEncrypt(cacheId, usageStatus);
        if (entryForEncrypt != null) {
            DataKeyCache.UsageStatus usageStatusNew = entryForEncrypt.getUsageStatus();
            if (checkExceedLImit(usageStatusNew)) {
                LOGGER.info("get encrypt dataKeyMaterials from cache success,  cacheId {}", cacheId);
                return entryForEncrypt.getDataKeyMaterials();
            }
            LOGGER.info("dataKeyMaterials of cacheId {} exceed massage limit,generate data key again", cacheId);
            entryForEncrypt.invalidate();
        }
        LOGGER.info("dataKeyMaterials of cacheId {} not exists or expired,generate data key again", cacheId);
        cryptoMeterialManager.getMaterialsForEncrypt(keyring, dataKeyMaterials, plaintTextLength);
        cache.putEntryForEncrypt(cacheId, dataKeyMaterials, usageStatus);
        return dataKeyMaterials;
    }

    private String getCacheId(DataKeyMaterials dataKeyMaterials) {
        MessageDigest digest = null;
        try {
            if (dataKeyMaterials.getCryptoAlgorithm() == CryptoAlgorithm.SM4_128_GCM_NOPADDING
                || dataKeyMaterials.getCryptoAlgorithm() == CryptoAlgorithm.SM4_128_CBC_PADDING) {
                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                digest = MessageDigest.getInstance(CACHE_ID_ALGORITHM_SM3, BouncyCastleProvider.PROVIDER_NAME);
            } else {
                digest = MessageDigest.getInstance(CACHE_ID_ALGORITHM_SHA, BouncyCastleProvider.PROVIDER_NAME);
            }
            digestAlgorithm(dataKeyMaterials.getCryptoAlgorithm(), digest);
            byte[] bytes = Utils.serializeContext(dataKeyMaterials.getEncryptionContexts());
            digestContext(digest, bytes);
            return Base64.getEncoder().encodeToString(digest.digest());
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.MESSAGE_DIGEST_ERROR.getMessage(), e);
        }
    }

    private void digestContext(MessageDigest digest, byte[] bytes) {
        if (bytes.length == 0) {
            digest.update((byte) 0);
        } else {
            digest.update(bytes);
        }
    }

    private void digestAlgorithm(CryptoAlgorithm algorithm, MessageDigest digest) {
        if (algorithm == null) {
            digest.update((byte) 0);
        } else {
            digest.update((byte) 1);
            digest.update(algorithm.getKeySpec().getBytes(StandardCharsets.UTF_8));
        }
    }

    private boolean checkExceedLImit(DataKeyCache.UsageStatus usageStatusNew) {
        return usageStatusNew.getBytesEncryptCount() <= maxByteLimit
            && usageStatusNew.getMessageEncryptCount() <= maxMessageLimit;
    }

    @Override
    public DataKeyMaterials getMaterialsForDecrypt(Keyring keyring, byte[] cipherText) throws IOException {
        DataMaterials dataMaterials = new DefaultSerializeHandler().deserialize(cipherText);
        CipherHeader headers = dataMaterials.getHeaders();
        String cacheId = getCacheId(headers.getAlgorithm(), headers.getEncryptionContext(),
            headers.getCiphertextDataKeys());
        DataKeyCache.DecryptCacheEntry entryForDecrypt = cache.getEntryForDecrypt(cacheId);
        if (entryForDecrypt != null) {
            LOGGER.info("get decrypt dataKeyMaterials from cache success,  cacheId {}", cacheId);
            return entryForDecrypt.getDataKeyMaterials();
        }
        LOGGER.info("dataKeyMaterials of cacheId {} not exists or expired,Re-decrypt the dataKey", cacheId);
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        dataKeyMaterials.setCiphertextDataKeys(dataMaterials.getHeaders().getCiphertextDataKeys());
        dataKeyMaterials.setCryptoAlgorithm(dataMaterials.getHeaders().getAlgorithm());
        dataKeyMaterials.setEncryptionContexts(dataMaterials.getHeaders().getEncryptionContext());
        dataKeyMaterials = keyring.decryptDataKey(dataKeyMaterials);
        cache.putEntryForDecrypt(cacheId, dataKeyMaterials);
        return dataKeyMaterials;
    }

    @Override
    public DataKeyMaterials getMaterialsForStreamDecrypt(Keyring keyring, InputStream inputStream) throws IOException {
        byte[] lengthByte = new byte[Short.SIZE / Byte.SIZE];
        int readShort = inputStream.read(lengthByte);
        if (readShort != lengthByte.length) {
            throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
        }
        ByteBuffer buffer = ByteBuffer.allocate(lengthByte.length).put(lengthByte);
        buffer.flip();
        short length = buffer.getShort();
        byte[] bytes = new byte[length];
        int read = inputStream.read(bytes);
        if (read != bytes.length) {
            throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
        }
        DataMaterials dataMaterials = new DefaultSerializeHandler().deserialize(bytes);
        String cacheId = getCacheId(dataMaterials.getHeaders().getAlgorithm(),
            dataMaterials.getHeaders().getEncryptionContext(), dataMaterials.getHeaders().getCiphertextDataKeys());
        DataKeyCache.DecryptCacheEntry entryForDecrypt = cache.getEntryForDecrypt(cacheId);
        if (entryForDecrypt != null) {
            LOGGER.info("get decrypt dataKeyMaterials from cache success,  cacheId {}", cacheId);
            return entryForDecrypt.getDataKeyMaterials();
        }
        LOGGER.info("dataKeyMaterials of cacheId {} not exists or expired,Re-decrypt the dataKey", cacheId);
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        dataKeyMaterials.setCiphertextDataKeys(dataMaterials.getHeaders().getCiphertextDataKeys());
        dataKeyMaterials.setCryptoAlgorithm(dataMaterials.getHeaders().getAlgorithm());
        dataKeyMaterials.setEncryptionContexts(dataMaterials.getHeaders().getEncryptionContext());
        keyring.decryptDataKey(dataKeyMaterials);
        cache.putEntryForDecrypt(cacheId, dataKeyMaterials);
        return dataKeyMaterials;
    }

    private String getCacheId(CryptoAlgorithm algorithm, Map<String, String> encryptionContext,
        List<CiphertextDataKey> ciphertextDataKeys) {
        MessageDigest messageDigest = null;
        try {
            if (algorithm == CryptoAlgorithm.SM4_128_GCM_NOPADDING) {
                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
                messageDigest = MessageDigest.getInstance(CACHE_ID_ALGORITHM_SM3, BouncyCastleProvider.PROVIDER_NAME);
            } else {
                messageDigest = MessageDigest.getInstance(CACHE_ID_ALGORITHM_SHA, BouncyCastleProvider.PROVIDER_NAME);
            }
            digestAlgorithm(algorithm, messageDigest);
            byte[] bytesContext = Utils.serializeContext(encryptionContext);
            digestContext(messageDigest, bytesContext);
            digestCiphertextDataKeys(messageDigest, ciphertextDataKeys);
            return Base64.getEncoder().encodeToString(messageDigest.digest());
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.MESSAGE_DIGEST_ERROR.getMessage(), e);
        }
    }

    private void digestCiphertextDataKeys(MessageDigest digest, List<CiphertextDataKey> ciphertextDataKeys) {
        if (ciphertextDataKeys == null) {
            digest.update((byte) 0);
        } else {
            digest.update((byte) 1);
            digest.update((byte) ciphertextDataKeys.size());
            TreeSet<CiphertextDataKey> set = new TreeSet<>((o1, o2) -> {
                byte[] dataKey = o1.getDataKey();
                byte[] dataKey1 = o2.getDataKey();
                int min = Math.min(dataKey.length, dataKey1.length);
                for (int i = 0; i < min; i++) {
                    int a = dataKey[i] & 0xFF;
                    int b = dataKey1[i] & 0xFF;
                    if (a != b) {
                        return a - b;
                    }
                }
                return dataKey.length - dataKey1.length;
            });
            set.addAll(ciphertextDataKeys);
            for (CiphertextDataKey ciphertextDataKey : set) {
                digest.update(ciphertextDataKey.toByteArray());
            }
        }
    }
}
