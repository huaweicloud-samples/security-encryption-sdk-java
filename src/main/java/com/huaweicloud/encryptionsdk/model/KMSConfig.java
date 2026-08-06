package com.huaweicloud.encryptionsdk.model;

/**
 * @description: kms配置类
 */
public class KMSConfig {
    /**
     * 地区。例如“cn-north-7"
     */
    private String region;

    /**
     * 主密钥id
     */
    private String keyId;

    /**
     * 项目id
     */
    private String projectId;

    /**
     * 节点域名
     */
    private String endPoint;

    public KMSConfig(String region, String keyId, String projectId, String endPoint) {
        this.region = region;
        this.keyId = keyId;
        this.projectId = projectId;
        this.endPoint = endPoint;
    }

    public KMSConfig(String region, String keyId, String projectId) {
        this.region = region;
        this.keyId = keyId;
        this.projectId = projectId;
        this.endPoint = null;
    }

    public KMSConfig(String region, String projectId) {
        this.region = region;
        this.keyId = null;
        this.projectId = projectId;
        this.endPoint = null;
    }

    public String getRegion() {
        return region;
    }

    public String getKeyId() {
        return keyId;
    }

    public String getProjectId() {
        return projectId;
    }

    public String getEndPoint() {
        return endPoint;
    }

}
