package com.huaweicloud.encryptionsdk.common;

import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public final class ECPrivateKeyLoader {

    private static final Logger LOGGER = LoggerFactory.getLogger(ECPrivateKeyLoader.class);

    public static PrivateKey load(String keyContent)
            throws HuaweicloudException {

        // 1. PEM格式
        if (keyContent.contains("-----BEGIN")) {
            try {
                return loadPem(keyContent);
            } catch (IOException e) {
                throw new HuaweicloudException(ErrorMessage.ACCESS_POINT_KEY_EXCEPTION.getMessage(), e);
            }
        }

        // 2. Base64格式
        try {
            byte[] der =
                    Base64.getMimeDecoder()
                            .decode(keyContent);

            return loadDer(der);
        } catch (Exception ignore) {
            LOGGER.debug("load Base64 private key error, msg is {}", ignore.getMessage());
        }

        throw new HuaweicloudException(ErrorMessage.ACCESS_POINT_KEY_EXCEPTION.getMessage());
    }

    private static PrivateKey loadPem(String pem)
            throws HuaweicloudException, IOException {

        try (PEMParser parser =
                     new PEMParser(
                             new StringReader(pem))) {

            Object obj = parser.readObject();

            JcaPEMKeyConverter converter =
                    new JcaPEMKeyConverter()
                            .setProvider(ProviderManager.getBcProvider());

            if (obj instanceof PEMKeyPair) {
                return converter
                        .getKeyPair((PEMKeyPair) obj)
                        .getPrivate();
            }

            if (obj instanceof PrivateKeyInfo) {
                return converter
                        .getPrivateKey(
                                (PrivateKeyInfo) obj);
            }

            throw new HuaweicloudException(ErrorMessage.ACCESS_POINT_KEY_EXCEPTION.getMessage());
        }
    }

    public static PrivateKey loadDer(byte[] der)
            throws HuaweicloudException {

        // PKCS8
        try {
            PKCS8EncodedKeySpec spec =
                    new PKCS8EncodedKeySpec(der);

            return KeyFactory
                    .getInstance("EC", ProviderManager.getBcProvider())
                    .generatePrivate(spec);
        } catch (Exception ignore) {
            LOGGER.debug("load pkcs8 private key error, msg is {}", ignore.getMessage());
        }

        // EC PRIVATE KEY
        try {
            PrivateKeyInfo privateKeyInfo =
                    PrivateKeyInfo.getInstance(der);

            return new JcaPEMKeyConverter()
                    .setProvider(ProviderManager.getBcProvider())
                    .getPrivateKey(privateKeyInfo);
        } catch (Exception ignore) {
            LOGGER.debug("load private key info error, msg is {}", ignore.getMessage());
        }

        throw new HuaweicloudException(ErrorMessage.ACCESS_POINT_KEY_EXCEPTION.getMessage());
    }
}
