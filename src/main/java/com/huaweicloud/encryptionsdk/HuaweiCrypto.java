package com.huaweicloud.encryptionsdk;

import com.huaweicloud.encryptionsdk.common.EcsMetadataService;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.exception.KeyringNotFoundException;
import com.huaweicloud.encryptionsdk.handler.CryptoHadler;
import com.huaweicloud.encryptionsdk.handler.DefaultCryptoHandler;
import com.huaweicloud.encryptionsdk.keyrings.Keyring;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.log.LogReporterManager;
import com.huaweicloud.encryptionsdk.meterialmanager.CacheCryptoMeterialManager;
import com.huaweicloud.encryptionsdk.meterialmanager.CryptoMeterialManager;
import com.huaweicloud.encryptionsdk.meterialmanager.DefaultCryptoMeterialsManager;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.enums.AccessPointType;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import org.apache.commons.codec.DecoderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Map;

public class HuaweiCrypto {

    private static final Logger LOGGER = LoggerFactory.getLogger(HuaweiCrypto.class);

    private CryptoHadler cryptoHandler;

    private HuaweiConfig huaweiConfig;

    private CryptoMeterialManager cryptoMeterialManager;

    private Keyring keyring;

    private LogReporterManager logReporterManager;

    public HuaweiCrypto(HuaweiConfig huaweiConfig) {
        this.huaweiConfig = huaweiConfig;
        huaweiConfig.setCryptoAlgorithm(huaweiConfig.getCryptoAlgorithm() == null
            ? CryptoAlgorithm.AES_128_GCM_NOPADDING
            : huaweiConfig.getCryptoAlgorithm());
        this.cryptoHandler = new DefaultCryptoHandler();
        this.cryptoMeterialManager = new DefaultCryptoMeterialsManager(huaweiConfig);
        this.logReporterManager = new LogReporterManager();

        if (huaweiConfig.getLogConfig() != null || huaweiConfig.isLocalLogOnly()) {
            logReporterManager.init(huaweiConfig);
        }
    }

    /**
     * 关闭日志上报管理器，释放LTS生产者资源。使用完毕后应调用此方法。
     */
    public void close() {
        logReporterManager.shutdown();
    }

    public HuaweiCrypto withCryptoMeterialManager(CryptoMeterialManager cryptoMeterialManager) {
        this.cryptoMeterialManager = cryptoMeterialManager;
        return this;
    }

    public HuaweiCrypto withKeyring(Keyring keyring) {
        this.keyring = keyring;
        if (keyring instanceof KMSKeyring) {
            ((KMSKeyring) keyring).setHuaweiConfig(huaweiConfig);
        }
        return this;
    }

    public CryptoResult<byte[]> encrypt(byte[] plaintText)
        throws NoSuchAlgorithmException, IOException, DecoderException {
        return encrypt(new EncryptRequest(Collections.emptyMap(), plaintText));
    }

    public CryptoResult<byte[]> encrypt(EncryptRequest request) {
        if (keyring == null) {
            throw new KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.getMessage());
        }

        DataKeyMaterials dataKeyMaterials = null;
        try {
            dataKeyMaterials = new DataKeyMaterials();
            dataKeyMaterials.setEncryptionContexts(request.getEncryptionContext());
            dataKeyMaterials.setCryptoAlgorithm(huaweiConfig.getCryptoAlgorithm());
            dataKeyMaterials.setPolicyId(request.getPolicyId());
            dataKeyMaterials.setKeyPolicy(request.getKeyPolicy());
            if (cryptoMeterialManager instanceof CacheCryptoMeterialManager
                && ((CacheCryptoMeterialManager) cryptoMeterialManager).getMaxByteLimit()
                < request.getPlainText().length) {
                throw new HuaweicloudException(ErrorMessage.DATA_EXCEED_LIMIT.getMessage());
            }
            dataKeyMaterials = cryptoMeterialManager.getMaterialsForEncrypt(keyring, dataKeyMaterials,
                request.getPlainText().length);
            CryptoResult<byte[]> result = cryptoHandler.encrypt(request, dataKeyMaterials);

            if (huaweiConfig.getLogConfig() != null || huaweiConfig.isLocalLogOnly()) {
                if (dataKeyMaterials.getKeyCapsule() != null) {
                    String keyId = dataKeyMaterials.getKeyCapsule().getKeyId();
                    Long encryptDataBytes = (long) request.getPlainText().length;
                    Long encryptOutputBytes = result.getDataLength();
                    String accessPointType = AccessPointType.getDisplayNameByCode(dataKeyMaterials.getKeyCapsule().getAccessPointType());
                    String instanceId = dataKeyMaterials.getKeyCapsule().getAccessPointType() == AccessPointType.ECS.getCode()
                        ? EcsMetadataService.getEcsInstanceId() : null;

                    logReporterManager.recordEncryptLog(
                        null,
                        encryptDataBytes,
                        null,
                        encryptOutputBytes,
                        keyId,
                        accessPointType,
                        instanceId
                    );
                }
            }

            return result;
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.CIPHER_EXCEPTION.getMessage(), e);

        }
    }

    public CryptoResult<byte[]> decrypt(byte[] cipherText) {
        if (keyring == null) {
            throw new KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.getMessage());
        }

        DataKeyMaterials dataKeyMaterials = null;
        try {
            dataKeyMaterials = cryptoMeterialManager.getMaterialsForDecrypt(keyring, cipherText);
            CryptoResult<byte[]> result = cryptoHandler.decrypt(cipherText, dataKeyMaterials);

            if (huaweiConfig.getLogConfig() != null || huaweiConfig.isLocalLogOnly()) {
                if (dataKeyMaterials.getKeyCapsule() != null) {
                    String keyId = dataKeyMaterials.getKeyCapsule().getKeyId();
                    Long decryptDataBytes = (long) cipherText.length;
                    Long decryptOutputBytes = result.getResult() != null ? (long) result.getResult().length : 0L;
                    String accessPointType = AccessPointType.getDisplayNameByCode(dataKeyMaterials.getKeyCapsule().getAccessPointType());
                    String instanceId = dataKeyMaterials.getKeyCapsule().getInstanceId();

                    logReporterManager.recordDecryptLog(
                        null,
                        decryptDataBytes,
                        null,
                        decryptOutputBytes,
                        keyId,
                        accessPointType,
                        instanceId
                    );
                }
            }

            return result;
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.DECRYPT_EXCEPTION.getMessage(), e);
        }
    }

    public CryptoResult<OutputStream> encrypt(InputStream inputStream, OutputStream outputStream,
        Map<String, String> encryptionContext) {
        if (keyring == null) {
            throw new KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.getMessage());
        }

        DataKeyMaterials dataKeyMaterials = null;
        try {
            long encryptDataBytes = inputStream.available();
            dataKeyMaterials = new DataKeyMaterials();
            dataKeyMaterials.setEncryptionContexts(
                encryptionContext == null ? Collections.emptyMap() : encryptionContext);
            dataKeyMaterials.setCryptoAlgorithm(huaweiConfig.getCryptoAlgorithm());
            if (cryptoMeterialManager instanceof CacheCryptoMeterialManager
                && ((CacheCryptoMeterialManager) cryptoMeterialManager).getMaxByteLimit() < encryptDataBytes) {
                throw new HuaweicloudException(ErrorMessage.DATA_EXCEED_LIMIT.getMessage());
            }
            dataKeyMaterials = cryptoMeterialManager.getMaterialsForEncrypt(keyring, dataKeyMaterials, encryptDataBytes);
            CryptoResult<OutputStream> cryptoResult = cryptoHandler.encrypt(inputStream, outputStream, dataKeyMaterials, encryptionContext);

            if (huaweiConfig.getLogConfig() != null || huaweiConfig.isLocalLogOnly()) {
                if (dataKeyMaterials.getKeyCapsule() != null) {
                    String keyId = dataKeyMaterials.getKeyCapsule().getKeyId();
                    String accessPointType = AccessPointType.getDisplayNameByCode(dataKeyMaterials.getKeyCapsule().getAccessPointType());
                    String instanceId = dataKeyMaterials.getKeyCapsule().getAccessPointType() == AccessPointType.ECS.getCode()
                        ? EcsMetadataService.getEcsInstanceId() : null;

                    logReporterManager.recordEncryptLog(
                        null,
                        encryptDataBytes,
                        null,
                        cryptoResult.getDataLength(),
                        keyId,
                        accessPointType,
                        instanceId
                    );
                }
            }
            return cryptoResult;
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.CIPHER_EXCEPTION.getMessage(), e);
        }
    }

    public CryptoResult<OutputStream> decrypt(InputStream inputStream, OutputStream outputStream) {
        if (keyring == null) {
            throw new KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.getMessage());
        }
        DataKeyMaterials dataKeyMaterials = null;
        try {
            long decryptDataBytes = inputStream.available();
            dataKeyMaterials = cryptoMeterialManager.getMaterialsForStreamDecrypt(keyring, inputStream);
            CryptoResult<OutputStream> cryptoResult = cryptoHandler.decrypt(inputStream, outputStream, dataKeyMaterials);

            if (huaweiConfig.getLogConfig() != null || huaweiConfig.isLocalLogOnly()) {
                if (dataKeyMaterials.getKeyCapsule() != null) {
                    String keyId = dataKeyMaterials.getKeyCapsule().getKeyId();
                    String accessPointType = AccessPointType.getDisplayNameByCode(dataKeyMaterials.getKeyCapsule().getAccessPointType());
                    String instanceId = dataKeyMaterials.getKeyCapsule().getInstanceId();

                    logReporterManager.recordDecryptLog(
                        null,
                        decryptDataBytes,
                        null,
                        null,
                        keyId,
                        accessPointType,
                        instanceId
                    );
                }
            }
            return cryptoResult;
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.DECRYPT_EXCEPTION.getMessage(), e);
        }
    }

    public CryptoResult<OutputStream> encrypt(String sourceFilePath, String targetFilePath,
                                              Map<String, String> encryptionContext) {
        if (keyring == null) {
            throw new KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.getMessage());
        }

        DataKeyMaterials dataKeyMaterials = null;
        File inputFile = new File(sourceFilePath);
        File outputFile = new File(targetFilePath);
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(inputFile), 64 * 1024);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(outputFile), 64 * 1024)) {
            long encryptDataBytes = bufferedInputStream.available();
            dataKeyMaterials = new DataKeyMaterials();
            dataKeyMaterials.setEncryptionContexts(
                    encryptionContext == null ? Collections.emptyMap() : encryptionContext);
            dataKeyMaterials.setCryptoAlgorithm(huaweiConfig.getCryptoAlgorithm());
            if (cryptoMeterialManager instanceof CacheCryptoMeterialManager
                    && ((CacheCryptoMeterialManager) cryptoMeterialManager).getMaxByteLimit() < encryptDataBytes) {
                throw new HuaweicloudException(ErrorMessage.DATA_EXCEED_LIMIT.getMessage());
            }
            dataKeyMaterials = cryptoMeterialManager.getMaterialsForEncrypt(keyring, dataKeyMaterials, encryptDataBytes);
            CryptoResult<OutputStream> cryptoResult = cryptoHandler.encrypt(bufferedInputStream, bufferedOutputStream, dataKeyMaterials, encryptionContext);

            if (huaweiConfig.getLogConfig() != null || huaweiConfig.isLocalLogOnly()) {
                if (dataKeyMaterials.getKeyCapsule() != null) {
                    String keyId = dataKeyMaterials.getKeyCapsule().getKeyId();
                    String accessPointType = AccessPointType.getDisplayNameByCode(dataKeyMaterials.getKeyCapsule().getAccessPointType());
                    String instanceId = dataKeyMaterials.getKeyCapsule().getAccessPointType() == AccessPointType.ECS.getCode()
                        ? EcsMetadataService.getEcsInstanceId() : null;

                    logReporterManager.recordEncryptLog(
                            inputFile.getName(),
                            encryptDataBytes,
                            outputFile.getName(),
                            outputFile.length(),
                            keyId,
                            accessPointType,
                            instanceId
                    );
                }
            }
            return cryptoResult;
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.CIPHER_EXCEPTION.getMessage(), e);
        }
    }

    public CryptoResult<OutputStream> decrypt(String sourceFilePath, String targetFilePath) {
        if (keyring == null) {
            throw new KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.getMessage());
        }
        DataKeyMaterials dataKeyMaterials = null;
        File inputFile = new File(sourceFilePath);
        File outputFile = new File(targetFilePath);
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(inputFile), 64 * 1024);
             BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(outputFile), 64 * 1024)) {
            long decryptDataBytes = bufferedInputStream.available();
            dataKeyMaterials = cryptoMeterialManager.getMaterialsForStreamDecrypt(keyring, bufferedInputStream);
            CryptoResult<OutputStream> cryptoResult = cryptoHandler.decrypt(bufferedInputStream, bufferedOutputStream, dataKeyMaterials);

            if (huaweiConfig.getLogConfig() != null || huaweiConfig.isLocalLogOnly()) {
                if (dataKeyMaterials.getKeyCapsule() != null) {
                    String keyId = dataKeyMaterials.getKeyCapsule().getKeyId();
                    String accessPointType = AccessPointType.getDisplayNameByCode(dataKeyMaterials.getKeyCapsule().getAccessPointType());
                    String instanceId = dataKeyMaterials.getKeyCapsule().getInstanceId();

                    logReporterManager.recordDecryptLog(
                            inputFile.getName(),
                            decryptDataBytes,
                            outputFile.getName(),
                            outputFile.length(),
                            keyId,
                            accessPointType,
                            instanceId
                    );
                }
            }
            return cryptoResult;
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.DECRYPT_EXCEPTION.getMessage(), e);
        }
    }

    LogReporterManager getLogReporterManager() {
        return logReporterManager;
    }
}
