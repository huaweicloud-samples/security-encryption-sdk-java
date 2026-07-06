package com.huaweicloud.encryptionsdk.common;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EcsMetadataService {

    private static final Logger LOGGER = LoggerFactory.getLogger(EcsMetadataService.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private static final String METADATA_BASE =
        "http://169.254.169.254/meta-data/latest/instance-identity";
    private static final String DOCUMENT_URL = METADATA_BASE + "/document";
    private static final String SIGNATURE_URL = METADATA_BASE + "/signature";

    private static volatile String cachedInstanceId;

    public static String getEcsInstanceId() {
        if (cachedInstanceId != null) {
            return cachedInstanceId;
        }
        synchronized (EcsMetadataService.class) {
            if (cachedInstanceId != null) {
                return cachedInstanceId;
            }
            try {
                String json = fetchMetadata(DOCUMENT_URL);
                if (json == null) {
                    return null;
                }
                JsonNode doc = OBJECT_MAPPER.readTree(json);
                if (doc.has("id")) {
                    cachedInstanceId = doc.get("id").asText();
                }
                return cachedInstanceId;
            } catch (Exception e) {
                LOGGER.error("Failed to get ECS instance id", e);
                return null;
            }
        }
    }

    public static String fetchIdentityDocument() {
        return fetchMetadata(DOCUMENT_URL);
    }

    public static String fetchIdentitySignature() {
        return fetchMetadata(SIGNATURE_URL);
    }

    private static volatile CloseableHttpClient httpClient;

    private static CloseableHttpClient getHttpClient() {
        if (httpClient == null) {
            synchronized (EcsMetadataService.class) {
                if (httpClient == null) {
                    httpClient = HttpClients.createDefault();
                }
            }
        }
        return httpClient;
    }

    private static String fetchMetadata(String url) {
        try {
            HttpGet request = new HttpGet(url);
            return getHttpClient().execute(request, response -> {
                int code = response.getCode();
                if (code >= 200 && code < 300) {
                    return EntityUtils.toString(response.getEntity());
                }
                LOGGER.debug("ECS metadata request failed, url={}, status={}", url, code);
                EntityUtils.consume(response.getEntity());
                return null;
            });
        } catch (Exception e) {
            LOGGER.debug("Failed to fetch ECS metadata from {}", url, e);
            return null;
        }
    }
}
