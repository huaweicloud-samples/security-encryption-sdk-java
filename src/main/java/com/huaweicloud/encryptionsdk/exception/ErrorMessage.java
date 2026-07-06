package com.huaweicloud.encryptionsdk.exception;

/**
 * @description: 错误信息
 */
public enum ErrorMessage {
    DECRYPT_EXCEPTION(1000, "process wrong when decrypt data"),
    CIPHER_EXCEPTION(1001, "process wrong when cipher data"),
    TAMPERED_EXCEPTION(1002, "Header integrity check failed."),
    ENCRYPT_EXCEPTION(1003, "encrypt error"),
    AK_NULL_EXCEPTION(1004, "ak of kms server should be not null"),
    SK_NULL_EXCEPTION(1005, "sk of kms server should be not null"),
    DATA_KEY_GENERATE_EXCEPTION(1006, "The data key generation type is not the specified type"),
    KMS_CREATE_KEY_EXCEPTION(1007, "create data key from kms error"),
    SERIALIZE_EXCEPTION(1008, "Failed to serialize cipher text headers"),
    DESERIALIZE_EXCEPTION(1009, "Failed to deserialize cipher text headers,the cipher header may be changed"),
    PUBLIC_KEY_PARSE_EXCEPTION(1010, "publicKey can not be parsed"),
    PRIVATE_KEY_PARSE_EXCEPTION(1011, "privateKey can not be parsed"),
    KEYRING_NULL_EXCEPTION(1012, "key ring should not be null"),
    KEYRING_NOT_FOUND_EXCEPTION(1013, "not found such type of Keyring"),
    KEYRING_NOT_MATCH_EXCEPTION(1014, "there is no master key match when decrypt data key"),
    DATA_EXCEED_LIMIT(1015, "plaintext data exceed cache limit"),
    MESSAGE_DIGEST_ERROR(1016, "MessageDigest error"),
    PROCESS_FILE_ERROR(1017, "process file error when encrypt or decrypt the file"),
    FILE_CHANGED_ERROR(1018, "the content of the file may be changed"),
    CONFIG_NULL_ERROR(1019, "the kms config information should not be null"),
    CIPHER_TEXT_CHANGED_ERROR(1020, "the cipher text may be changed"),
    NOT_FOUND_CIPHER_TEXT_DATA_KEY(1021, "cipher header may be changed,the count of data key should not less than 0"),
    NOT_SUPPORT_DISCOVERY_DECRYPT(1022, "the cipher text not support discovery Keyring"),
    ENCRYPT_DATA_KEY_EXCEPTION(1023, "encrypt data key error,please confirm your information is right"),
    CACHE_PARAM_LESS_THAN_ZERO(1024, "the param of cache should not less than 0!"),
    MASTER_KEY_SHOULD_NOT_NULL(1025, "Master Key should not null"),
    SOURCE_FILE_INVALID(1026, "The length of the source file is insufficient."),
    KMS_CREATE_KEY_CAPSULE_EXCEPTION(1027, "create key capsule from KMS error"),
    PARSE_KEY_CAPSULE_EXCEPTION(1028, "parse key capsule exception"),
    DECRYPT_KEY_CAPSULE_EXCEPTION(1029, "decrypt key capsule exception"),
    KEY_CAPSULE_NULL(1030, "key capsule is null"),
    UNSUPPORTED_ACCESS_POINT_TYPE(1031, "unsupported access point type"),
    CIPHER_TEXT_DATA_KEY_NOT_NULL(1032, "the cipher text data key should not be null"),
    END_POINT_NOT_NULL(1033, "the region is not support or endpoint should not be null"),
    KEY_CAPSULE_REGION_NOT_FOUND(1034, "the region of key capsule is not found, region is "),
    ACCESS_POINT_KEY_EXCEPTION(1035, "The access point key material is incorrectly parsed."),
    COLLECT_PROOF_EXCEPTION(1036, "Failed to collect the proof document."),
    GET_PUB_KEY_EXCEPTION(1037, "Get ecc public key from private key error.");

    private String message;

    private int code;

    ErrorMessage(int code, String message) {
        this.message = message;
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public ErrorMessage setMessage(String message) {
        this.message = message;
        return this;
    }

}
