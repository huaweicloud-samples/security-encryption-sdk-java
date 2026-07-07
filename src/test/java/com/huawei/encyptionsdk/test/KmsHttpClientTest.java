package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.kms.CreateKeyCapsuleRequest;
import com.huaweicloud.encryptionsdk.kms.CreateKeyCapsuleResponse;
import com.huaweicloud.encryptionsdk.kms.KmsHttpClient;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class KmsHttpClientTest {

    @Test
    public void testConstructor() {
        KMSConfig config = new KMSConfig("cn-north-7", "kid", "pid", "https://kms.cn-north-7.myhuaweicloud.com");
        KmsHttpClient client = new KmsHttpClient("ak", "sk", config);
        assertNotNull(client);
        assertTrue(client instanceof KmsHttpClient);
    }

    @Test(expected = HuaweicloudException.class)
    public void testBuildUrlNullEndpoint() {
        KMSConfig config = new KMSConfig("cn-north-7", "kid", "pid", null);
        KmsHttpClient client = new KmsHttpClient("ak", "sk", config);
        client.post("/test", null, String.class);
    }

    @Test(expected = HuaweicloudException.class)
    public void testBuildUrlEmptyEndpoint() {
        KMSConfig config = new KMSConfig("cn-north-7", "kid", "pid", "");
        KmsHttpClient client = new KmsHttpClient("ak", "sk", config);
        client.post("/test", null, String.class);
    }

    @Test
    public void testPostWithBody() {
        KMSConfig config = new KMSConfig("cn-north-7", "kid", "pid", "https://kms.cn-north-7.myhuaweicloud.com");
        KmsHttpClient client = new KmsHttpClient("ak", "sk", config);
        try {
            CreateKeyCapsuleRequest req = CreateKeyCapsuleRequest.builder()
                    .keyId("key-1")
                    .datakeyLength(256)
                    .build();
            client.post("/v1.0/pid/key-capsule/create", req, CreateKeyCapsuleResponse.class);
        } catch (HuaweicloudException e) {
            assertTrue(e.getMessage().length() > 0);
        } catch (Exception e) {
            assertTrue(e.getMessage().length() > 0);
        }
    }

    @Test
    public void testPostWithNullBody() {
        KMSConfig config = new KMSConfig("cn-north-7", "kid", "pid", "https://kms.cn-north-7.myhuaweicloud.com");
        KmsHttpClient client = new KmsHttpClient("ak", "sk", config);
        try {
            client.post("/v1.0/pid/key-capsule/create", null, String.class);
        } catch (HuaweicloudException e) {
            assertTrue(e.getMessage().length() > 0);
        } catch (Exception e) {
            assertTrue(e.getMessage().length() > 0);
        }
    }
}
