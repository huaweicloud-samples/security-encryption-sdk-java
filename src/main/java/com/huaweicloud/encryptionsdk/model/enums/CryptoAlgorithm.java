// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package com.huaweicloud.encryptionsdk.model.enums;

import com.huaweicloud.encryptionsdk.common.Constants;

/**
 * Describes the cryptographic algorithms available for the sdk.
 */
public enum CryptoAlgorithm {

    /**
     * AES/GCM/NoPadding 128
     */
    AES_128_GCM_NOPADDING("AES_128", "AES/GCM/NoPadding", 16, 12, 16, 16, (short) 1, (byte) 1, "AES", 128),
    /**
     * AES/GCM/NoPadding 256
     */
    AES_256_GCM_NOPADDING("AES_256", "AES/GCM/NoPadding", 32, 12, 16, 16, (short) 2, (byte) 1, "AES", 256),

    /**
     * SM4/GCM/NoPadding 128
     */
    SM4_128_GCM_NOPADDING("SM4_128", "SM4/GCM/NoPadding", 16, 12, 16, 16, (short) 3, (byte) 1, "SM4", 128),
    /**
     * SM4/CBC/Padding 128
     */
    SM4_128_CBC_PADDING("SM4_128", "SM4/CBC/PKCS5Padding", 16, 16, 16, 16, (short) 4, (byte) 1, "SM4", 128),
    ;

    private byte version;

    private String keySpec;

    private String cryptoAlg;

    private int keyLen;

    private int ivLen;

    private int tagLen;

    private int blockSize;

    private short value;

    private String secKeyAlgorithm;

    private int datakeyLength;

    CryptoAlgorithm(String keySpec, String cryptoAlg, int keyLen, int ivLen, int tagLen, int blockSize, short value,
        byte version, String secKeyAlgorithm, int datakeyLength) {
        this.keySpec = keySpec;
        this.cryptoAlg = cryptoAlg;
        this.keyLen = keyLen;
        this.ivLen = ivLen;
        this.tagLen = tagLen;
        this.blockSize = blockSize;
        this.value = value;
        this.version = version;
        this.secKeyAlgorithm = secKeyAlgorithm;
        this.datakeyLength = datakeyLength;
    }

    public static CryptoAlgorithm getAlgorithm(int algorithmValue) {
        for (CryptoAlgorithm algorithm : CryptoAlgorithm.values()) {
            if (algorithm.value == algorithmValue) {
                return algorithm;
            }
        }
        return null;
    }

    public String getAlgorithmName() {
        return this.keySpec.split(Constants.KEY_SPEC_DELIMITER)[0];
    }

    public byte getVersion() {
        return version;
    }

    public void setVersion(byte version) {
        this.version = version;
    }

    public String getKeySpec() {
        return keySpec;
    }

    public void setKeySpec(String keySpec) {
        this.keySpec = keySpec;
    }

    public String getCryptoAlg() {
        return cryptoAlg;
    }

    public void setCryptoAlg(String cryptoAlg) {
        this.cryptoAlg = cryptoAlg;
    }

    public int getKeyLen() {
        return keyLen;
    }

    public void setKeyLen(int keyLen) {
        this.keyLen = keyLen;
    }

    public int getIvLen() {
        return ivLen;
    }

    public void setIvLen(int ivLen) {
        this.ivLen = ivLen;
    }

    public int getTagLen() {
        return tagLen;
    }

    public void setTagLen(int tagLen) {
        this.tagLen = tagLen;
    }

    public int getBlockSize() {
        return blockSize;
    }

    public void setBlockSize(int blockSize) {
        this.blockSize = blockSize;
    }

    public short getValue() {
        return value;
    }

    public void setValue(short value) {
        this.value = value;
    }

    public String getSecKeyAlgorithm() {
        return secKeyAlgorithm;
    }

    public int getDatakeyLength() {
        return datakeyLength;
    }

    public String getCryptoMode() {
        String[] strs = getCryptoAlg().split("/");
        return strs[1];
    }
}
