package com.huaweicloud.encryptionsdk.log;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 日志上报管理器，负责初始化日志配置、记录加解密操作日志、关闭日志资源。
 * 支持两种模式：本地日志模式（localLogOnly）和LTS远程上报模式。
 * 每个HuaweiCrypto实例持有自己的LogReporterManager。
 */
public class LogReporterManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(LogReporterManager.class);

    /** LTS日志生产者，仅在LTS远程上报模式下初始化 */
    private LTSSDKProducer ltsProducer;

    /** 日志配置 */
    private LogConfig logConfig;

    /** 是否仅本地日志模式 */
    private boolean localLogOnly = false;

    /** 是否已完成初始化 */
    private volatile boolean initialized = false;

    /** 初始化重试次数 */
    private int initRetryCount = 0;

    /** 最大初始化重试次数，超过后放弃重试 */
    private static final int MAX_INIT_RETRY_COUNT = 3;

    public LogReporterManager() {
    }

    /**
     * 初始化日志上报管理器。根据配置决定使用本地日志模式或LTS远程上报模式。
     * 若已初始化则跳过；若配置无效（logConfig为null且localLogOnly为false）则标记initialized为true并禁用日志功能，
     * 避免重复初始化尝试。
     *
     * @param config 华为加密配置
     */
    public synchronized void init(HuaweiConfig config) {
        if (initialized) {
            LOGGER.debug("LogReporterManager is already initialized");
            return;
        }

        if (initRetryCount >= MAX_INIT_RETRY_COUNT) {
            LOGGER.warn("LogReporterManager init has exceeded max retry count ({}), giving up", MAX_INIT_RETRY_COUNT);
            return;
        }

        if (config.getLogConfig() == null && !config.isLocalLogOnly()) {
            LOGGER.info("Log config is not provided and localLogOnly is false, logging is disabled");
            return;
        }

        // 当logConfig为空时（localLogOnly模式），使用默认配置
        if (config.getLogConfig() != null) {
            this.logConfig = config.getLogConfig();
        } else {
            this.logConfig = LogConfig.builder().build();
        }

        if (config.isLocalLogOnly()) {
            this.localLogOnly = true;
            initialized = true;
            LOGGER.info("LogReporterManager initialized with local log only mode");
            return;
        }

        try {
            if (logConfig.getProjectId() == null) {
                String projectId = "default";
                if (config.getKmsConfigList() != null && !config.getKmsConfigList().isEmpty()) {
                    projectId = config.getKmsConfigList().get(0).getProjectId();
                }
                logConfig.setProjectId(projectId);
            }

            this.ltsProducer = new LTSSDKProducer(
                config.getAk(),
                config.getSk(),
                logConfig.getProjectId(),
                logConfig.getRegion(),
                logConfig
            );

            initialized = true;
            LOGGER.info("LogReporterManager initialized successfully with LTS mode");
            LOGGER.info("Log config: batchCountThreshold={}, lingerMs={}, ioThreadCount={}",
                logConfig.getBatchCountThreshold(), logConfig.getLingerMs(), logConfig.getIoThreadCount());
        } catch (Exception e) {
            initRetryCount++;
            LOGGER.error("Failed to initialize LogReporterManager (attempt {}/{})", initRetryCount, MAX_INIT_RETRY_COUNT, e);
            if (logConfig.isFailOnBackupDirMissing()) {
                throw e;
            }
        }
    }

    /**
     * 记录加密操作日志
     *
     * @param encryptFileName    加密输入文件名
     * @param encryptDataBytes   加密输入数据字节数
     * @param encryptOutputFileName 加密输出文件名
     * @param encryptOutputBytes 加密输出数据字节数
     * @param keyId              密钥ID
     * @param accessPointType    接入点类型
     * @param instanceId         实例ID
     */
    public void recordEncryptLog(
        String encryptFileName,
        Long encryptDataBytes,
        String encryptOutputFileName,
        Long encryptOutputBytes,
        String keyId,
        String accessPointType,
        String instanceId
    ) {
        recordLog("encrypt", encryptFileName, encryptDataBytes,
            encryptOutputFileName, encryptOutputBytes,
            keyId, accessPointType, instanceId);
    }

    /**
     * 记录解密操作日志
     *
     * @param decryptFileName    解密输入文件名
     * @param decryptDataBytes   解密输入数据字节数
     * @param decryptOutputFileName 解密输出文件名
     * @param decryptOutputBytes 解密输出数据字节数
     * @param keyId              密钥ID
     * @param accessPointType    接入点类型
     * @param instanceId         实例ID
     */
    public void recordDecryptLog(
        String decryptFileName,
        Long decryptDataBytes,
        String decryptOutputFileName,
        Long decryptOutputBytes,
        String keyId,
        String accessPointType,
        String instanceId
    ) {
        recordLog("decrypt", decryptFileName, decryptDataBytes,
            decryptOutputFileName, decryptOutputBytes,
            keyId, accessPointType, instanceId);
    }

    private void recordLog(
        String operation,
        String fileName,
        Long dataBytes,
        String outputFileName,
        Long outputBytes,
        String keyId,
        String accessPointType,
        String instanceId
    ) {
        if (!initialized) {
            return;
        }

        try {
            String logContent = LtsStructLogBuilder.buildStructLog(
                operation, fileName, dataBytes,
                outputFileName, outputBytes,
                keyId, accessPointType, instanceId
            );

            if (localLogOnly) {
                LOGGER.info("[LOCAL_LOG] {}", logContent);
                return;
            }

            if (ltsProducer != null) {
                ltsProducer.sendLog(logContent);
            }
            LOGGER.info("Recorded {} log for keyId: {}, dataBytes: {}, accessPointType: {}",
                operation, desensitize(keyId), dataBytes, accessPointType);
        } catch (Exception e) {
            LOGGER.error("Failed to record {} operation log", operation, e);
        }
    }

    /**
     * 关闭日志上报管理器，释放LTS生产者资源。
     * 并记录错误日志以便排查。
     */
    public synchronized void shutdown() {
        if (!initialized) {
            return;
        }

        if (ltsProducer != null) {
            try {
                ltsProducer.close();
            } catch (Exception e) {
                LOGGER.error("Failed to close LTS producer during shutdown, will retry on next shutdown call", e);
                return;
            }
            ltsProducer = null;
        }
        initialized = false;
        initRetryCount = 0;
        LOGGER.info("LogReporterManager shutdown successfully");
    }

    /**
     * 是否已完成初始化
     *
     * @return 初始化状态
     */
    public boolean isInitialized() {
        return initialized;
    }

    /**
     * 获取LTS生产者实例
     *
     * @return LTSSDKProducer实例，未初始化LTS模式时返回null
     */
    public LTSSDKProducer getLtsProducer() {
        return ltsProducer;
    }

    /**
     * 对敏感信息进行脱敏处理，保留首尾各2个字符，中间用****替代
     *
     * @param value 待脱敏的原始值
     * @return 脱敏后的字符串
     */
    public static String desensitize(String value) {
        if (value == null || value.length() <= 4) {
            return "****";
        }
        return value.substring(0, 2) + "****" + value.substring(value.length() - 2);
    }
}
