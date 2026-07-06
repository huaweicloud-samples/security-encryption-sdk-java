package com.huaweicloud.encryptionsdk.kms;

import com.cloud.apigateway.sdk.utils.Client;
import com.cloud.apigateway.sdk.utils.Request;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KmsHttpClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(KmsHttpClient.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private static final String SIGNATURE_ALGORITHM = "SDK-HMAC-SHA256";
    private static final String CONTENT_TYPE_JSON = "application/json";
    private static final int CONNECT_TIMEOUT_SECONDS = 10;
    private static final int SOCKET_TIMEOUT_SECONDS = 10;
    private static final int MAX_CONN_TOTAL = 50;
    private static final int MAX_CONN_PER_ROUTE = 20;

    private static final CloseableHttpClient SHARED_CLIENT;

    static {
        PoolingHttpClientConnectionManager connManager =
                PoolingHttpClientConnectionManagerBuilder.create()
                        .setDefaultConnectionConfig(
                                ConnectionConfig.custom()
                                        .setConnectTimeout(
                                                Timeout.ofSeconds(CONNECT_TIMEOUT_SECONDS))
                                        .build())
                        .build();

        connManager.setMaxTotal(MAX_CONN_TOTAL);
        connManager.setDefaultMaxPerRoute(MAX_CONN_PER_ROUTE);

        RequestConfig requestConfig = RequestConfig.custom()
                .setResponseTimeout(
                        Timeout.ofSeconds(SOCKET_TIMEOUT_SECONDS))
                .build();
        SHARED_CLIENT = HttpClients.custom()
                .setConnectionManager(connManager)
                .setDefaultRequestConfig(requestConfig)
                .build();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                SHARED_CLIENT.close();
            } catch (Exception e) {
                LOGGER.debug("Failed to close shared HttpClient", e);
            }
        }));
    }

    private final String ak;
    private final String sk;
    private final KMSConfig kmsConfig;

    public KmsHttpClient(String ak, String sk, KMSConfig kmsConfig) {
        this.ak = ak;
        this.sk = sk;
        this.kmsConfig = kmsConfig;
    }

    public <T> T post(String uri, Object body, Class<T> responseType) {
        return execute("POST", uri, body, responseType);
    }

    public <T> T get(String uri, Class<T> responseType) {
        return execute("GET", uri, null, responseType);
    }

    public <T> T put(String uri, Object body, Class<T> responseType) {
        return execute("PUT", uri, body, responseType);
    }

    public <T> T delete(String uri, Object body, Class<T> responseType) {
        return execute("DELETE", uri, body, responseType);
    }

    private <T> T execute(String method, String uri, Object body, Class<T> responseType) {
        String url = buildUrl(uri);
        String jsonBody = null;
        if (body != null) {
            try {
                jsonBody = OBJECT_MAPPER.writeValueAsString(body);
            } catch (JsonProcessingException e) {
                throw new HuaweicloudException("Failed to serialize request body", e);
            }
        }

        try {
            Request signRequest = new Request();
            signRequest.setKey(ak);
            signRequest.setSecret(sk);
            signRequest.setMethod(method);
            signRequest.setUrl(url);
            signRequest.addHeader("Content-Type", CONTENT_TYPE_JSON);
            if (jsonBody != null) {
                signRequest.setBody(jsonBody);
            }

            HttpUriRequestBase signedRequest = Client.sign(signRequest, SIGNATURE_ALGORITHM);
            if (jsonBody != null) {
                signedRequest.setEntity(new StringEntity(jsonBody, ContentType.APPLICATION_JSON));
            }

            return SHARED_CLIENT.execute(signedRequest, response -> {
                String responseBody = EntityUtils.toString(response.getEntity());
                if (response.getHeader("X-Request-Id") != null) {
                    LOGGER.info("[EncryptionSDK] X-Request-Id is {}", response.getHeader("X-Request-Id").getValue());
                }
                if (response.getCode() != 200) {
                    throw new HuaweicloudException(
                            "KMS API call failed, status=" + response.getCode()
                            + ", body=" + responseBody);
                }
                return OBJECT_MAPPER.readValue(responseBody, responseType);
            });
        } catch (HuaweicloudException e) {
            throw e;
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.KMS_CREATE_KEY_EXCEPTION.getMessage(), e);
        }
    }

    private String buildUrl(String uri) {
        String endpoint = kmsConfig.getEndPoint();
        if (endpoint == null || endpoint.isEmpty()) {
            throw new HuaweicloudException(ErrorMessage.END_POINT_NOT_NULL.getMessage());
        }
        return endpoint + "/v1.0/" + kmsConfig.getProjectId() + uri;
    }
}