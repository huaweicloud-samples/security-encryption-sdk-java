package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;

public class ErrorMessageTest {

    @Test
    public void testAllErrorMessages() {
        for (ErrorMessage em : ErrorMessage.values()) {
            assertNotNull(em.getMessage());
        }
    }

    @Test
    public void testNewErrorMessages() {
        assertNotNull(ErrorMessage.KMS_CREATE_KEY_CAPSULE_EXCEPTION.getMessage());
        assertNotNull(ErrorMessage.PARSE_KEY_CAPSULE_EXCEPTION.getMessage());
        assertNotNull(ErrorMessage.DECRYPT_KEY_CAPSULE_EXCEPTION.getMessage());
        assertNotNull(ErrorMessage.KEY_CAPSULE_NULL.getMessage());
        assertNotNull(ErrorMessage.UNSUPPORTED_ACCESS_POINT_TYPE.getMessage());
        assertNotNull(ErrorMessage.CIPHER_TEXT_DATA_KEY_NOT_NULL.getMessage());
        assertNotNull(ErrorMessage.END_POINT_NOT_NULL.getMessage());
        assertNotNull(ErrorMessage.KEY_CAPSULE_REGION_NOT_FOUND.getMessage());
        assertNotNull(ErrorMessage.ACCESS_POINT_KEY_EXCEPTION.getMessage());
        assertNotNull(ErrorMessage.COLLECT_PROOF_EXCEPTION.getMessage());
        assertNotNull(ErrorMessage.GET_PUB_KEY_EXCEPTION.getMessage());
    }
}
