package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.common.EcsMetadataService;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.junit.Test;
import org.mockito.Mockito;

import java.lang.reflect.Field;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;

public class EcsMetadataServiceTest {

    @Test
    public void testGetEcsInstanceIdReturnsNullWhenNotInEcs() {
        resetCache();
        resetHttpClient();
        String id = EcsMetadataService.getEcsInstanceId();
        assertNull(id);
    }

    @Test
    public void testFetchIdentityDocumentReturnsNullWhenNotInEcs() {
        resetHttpClient();
        String doc = EcsMetadataService.fetchIdentityDocument();
        assertNull(doc);
    }

    @Test
    public void testFetchIdentitySignatureReturnsNullWhenNotInEcs() {
        resetHttpClient();
        String sig = EcsMetadataService.fetchIdentitySignature();
        assertNull(sig);
    }

    @Test
    public void testGetEcsInstanceIdWithCachedValue() {
        resetCache();
        resetHttpClient();
        setCache("cached-instance-123");
        String id = EcsMetadataService.getEcsInstanceId();
        assertEquals("cached-instance-123", id);
    }

    @Test
    public void testGetEcsInstanceIdWithMockedHttpClient() throws Exception {
        resetCache();
        resetHttpClient();

        String jsonWithId = "{\"id\":\"instance-abc\",\"region\":\"cn-north-1\"}";
        CloseableHttpClient mockClient = Mockito.mock(CloseableHttpClient.class);
        doAnswer(invocation -> {
            HttpClientResponseHandler<String> handler = invocation.getArgument(1);
            ClassicHttpResponse response = Mockito.mock(ClassicHttpResponse.class);
            Mockito.when(response.getCode()).thenReturn(200);
            Mockito.when(response.getEntity()).thenReturn(new StringEntity(jsonWithId));
            return handler.handleResponse(response);
        }).when(mockClient).execute(any(HttpGet.class), any(HttpClientResponseHandler.class));

        setHttpClient(mockClient);
        String id = EcsMetadataService.getEcsInstanceId();
        assertEquals("instance-abc", id);

        String id2 = EcsMetadataService.getEcsInstanceId();
        assertEquals("instance-abc", id2);

        resetCache();
        resetHttpClient();
    }

    @Test
    public void testGetEcsInstanceIdJsonWithoutId() throws Exception {
        resetCache();
        resetHttpClient();

        String jsonWithoutId = "{\"region\":\"cn-north-1\"}";
        CloseableHttpClient mockClient = Mockito.mock(CloseableHttpClient.class);
        doAnswer(invocation -> {
            HttpClientResponseHandler<String> handler = invocation.getArgument(1);
            ClassicHttpResponse response = Mockito.mock(ClassicHttpResponse.class);
            Mockito.when(response.getCode()).thenReturn(200);
            Mockito.when(response.getEntity()).thenReturn(new StringEntity(jsonWithoutId));
            return handler.handleResponse(response);
        }).when(mockClient).execute(any(HttpGet.class), any(HttpClientResponseHandler.class));

        setHttpClient(mockClient);
        String id = EcsMetadataService.getEcsInstanceId();
        assertNull(id);

        resetCache();
        resetHttpClient();
    }

    @Test
    public void testGetEcsInstanceIdNon2xxResponse() throws Exception {
        resetCache();
        resetHttpClient();

        CloseableHttpClient mockClient = Mockito.mock(CloseableHttpClient.class);
        doAnswer(invocation -> {
            HttpClientResponseHandler<String> handler = invocation.getArgument(1);
            ClassicHttpResponse response = Mockito.mock(ClassicHttpResponse.class);
            Mockito.when(response.getCode()).thenReturn(404);
            Mockito.when(response.getEntity()).thenReturn(new StringEntity("not found"));
            return handler.handleResponse(response);
        }).when(mockClient).execute(any(HttpGet.class), any(HttpClientResponseHandler.class));

        setHttpClient(mockClient);
        String id = EcsMetadataService.getEcsInstanceId();
        assertNull(id);

        resetCache();
        resetHttpClient();
    }

    @Test
    public void testGetEcsInstanceIdException() throws Exception {
        resetCache();
        resetHttpClient();

        CloseableHttpClient mockClient = Mockito.mock(CloseableHttpClient.class);
        doAnswer(invocation -> {
            throw new HuaweicloudException("connection refused");
        }).when(mockClient).execute(any(HttpGet.class), any(HttpClientResponseHandler.class));

        setHttpClient(mockClient);
        String id = EcsMetadataService.getEcsInstanceId();
        assertNull(id);

        resetCache();
        resetHttpClient();
    }

    private void resetCache() {
        try {
            Field field = EcsMetadataService.class.getDeclaredField("cachedInstanceId");
            field.setAccessible(true);
            field.set(null, null);
        } catch (Exception e) {
            throw new HuaweicloudException(e);
        }
    }

    private void setCache(String value) {
        try {
            Field field = EcsMetadataService.class.getDeclaredField("cachedInstanceId");
            field.setAccessible(true);
            field.set(null, value);
        } catch (Exception e) {
            throw new HuaweicloudException(e);
        }
    }

    private void resetHttpClient() {
        try {
            Field field = EcsMetadataService.class.getDeclaredField("httpClient");
            field.setAccessible(true);
            field.set(null, null);
        } catch (Exception e) {
            throw new HuaweicloudException(e);
        }
    }

    private void setHttpClient(CloseableHttpClient client) {
        try {
            Field field = EcsMetadataService.class.getDeclaredField("httpClient");
            field.setAccessible(true);
            field.set(null, client);
        } catch (Exception e) {
            throw new HuaweicloudException(e);
        }
    }
}
