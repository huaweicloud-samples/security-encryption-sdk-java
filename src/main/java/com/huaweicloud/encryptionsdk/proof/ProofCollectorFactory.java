package com.huaweicloud.encryptionsdk.proof;

import com.huaweicloud.encryptionsdk.proof.collector.CceProofCollector;
import com.huaweicloud.encryptionsdk.proof.collector.EcsProofCollector;
import com.huaweicloud.encryptionsdk.proof.collector.KeyPairProofCollector;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 证明文档收集器工厂
 * 负责管理和提供各种场景的证明收集器
 */
public class ProofCollectorFactory {

    private static final Map<Integer, ProofCollector> COLLECTORS = new ConcurrentHashMap<>();

    static {
        // 注册默认的证明收集器
        registerCollector(1, new EcsProofCollector());
        registerCollector(2, new KeyPairProofCollector());
        registerCollector(3, new CceProofCollector());
    }

    /**
     * 注册自定义证明收集器
     *
     * @param type      接入点类型
     * @param collector 证明收集器实例
     */
    public static void registerCollector(int type, ProofCollector collector) {
        if (collector == null) {
            throw new IllegalArgumentException("Type and collector cannot be null");
        }
        COLLECTORS.put(type, collector);
    }

    /**
     * 获取证明收集器
     *
     * @param type 接入点类型
     * @return 证明收集器
     * @throws IllegalArgumentException 当类型不支持时
     */
    public static ProofCollector getCollector(Integer type) {
        if (type == null) {
            throw new IllegalArgumentException("Access point type cannot be null");
        }
        ProofCollector collector = COLLECTORS.get(type);
        if (collector == null) {
            throw new IllegalArgumentException(
                "Unsupported access point type: " + type + ". Supported types: " + COLLECTORS.keySet());
        }
        return collector;
    }

    /**
     * 收集证明文档
     *
     * @param proofInfo 接入点配置
     * @return 证明文档
     */
    public static AttestationDocument collect(ProofInfo proofInfo) {
        if (proofInfo == null) {
            throw new IllegalArgumentException("AccessPointConfig cannot be null");
        }
        int type = proofInfo.getType();
        ProofCollector collector = getCollector(type);
        return collector.collect(proofInfo);
    }
}