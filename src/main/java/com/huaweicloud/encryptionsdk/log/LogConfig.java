package com.huaweicloud.encryptionsdk.log;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 日志上报配置（最终版）
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LogConfig {

    // ========================================
    // 基础配置
    // ========================================

    /**
     * 日志组ID（UUID格式，标准日志上报使用）
     * 如果为空，则根据logGroupName自动解析
     */
    private String logGroupId;

    /**
     * 日志流ID（UUID格式，标准日志上报使用）
     * 如果为空，则根据logStreamName自动解析
     */
    private String logStreamId;

    /**
     * 日志组名称（用于自动解析logGroupId）
     */
    @Builder.Default
    private String logGroupName = "DSC";

    /**
     * 日志流名称（用于自动解析logStreamId）
     */
    @Builder.Default
    private String logStreamName = "crypto_operation_log";

    /**
     * LTS服务区域
     */
    private String region;

    /**
     * 项目ID
     */
    private String projectId;

    // ========================================
    // 上报频率配置（特性要求）
    // ========================================

    /**
     * 缓冲区默认1000条记录
     */
    @Builder.Default
    private int batchCountThreshold = 1000;

    /**
     * 批量大小阈值（字节）
     */
    @Builder.Default
    private int batchSizeThresholdInBytes = 524288;

    /**
     * 异步任务每30秒执行一次（毫秒）
     */
    @Builder.Default
    private int lingerMs = 30000;

    // ========================================
    // 缓冲区配置
    // ========================================

    /**
     * 单个Producer能缓存的日志大小上限
     */
    @Builder.Default
    private int totalSizeInBytes = 104857600;

    /**
     * 发送日志时阻塞时间（毫秒）
     */
    @Builder.Default
    private long maxBlockMs = 0L;

    // ========================================
    // 性能配置
    // ========================================

    /**
     * 执行日志发送任务的线程池大小
     */
    @Builder.Default
    private int ioThreadCount = Runtime.getRuntime().availableProcessors();

    // ========================================
    // 重试配置
    // ========================================

    /**
     * 发送日志失败后重试次数
     */
    @Builder.Default
    private int retries = 5;

    /**
     * 首次重试的退避时间（毫秒）
     */
    @Builder.Default
    private long baseRetryBackoffMs = 100L;

    /**
     * 重试的最大退避时间（毫秒）
     */
    @Builder.Default
    private long maxRetryBackoffMs = 500L;

    // ========================================
    // 其他配置
    // ========================================

    /**
     * 是否开启跨云上报日志（仅开发调测使用）
     */
    @Builder.Default
    private boolean enableLocalTest = false;

    // ========================================
    // 日志备份配置（新增）
    // ========================================

    /**
     * 失败日志备份目录
     * 默认：用户主目录/lts_log_backup
     */
    @Builder.Default
    private String backupDir = System.getProperty("user.home") + java.io.File.separator + "lts_log_backup";

    /**
     * 最大备份文件大小（字节）
     */
    @Builder.Default
    private long maxBackupFileSize = 10 * 1024 * 1024;

    /**
     * 启动时恢复失败的日志
     */
    @Builder.Default
    private boolean enableRecoveryOnStartup = true;

    /**
     * 恢复时的批量大小
     */
    @Builder.Default
    private int recoveryBatchSize = 1000;

    /**
     * 恢复批次之间的间隔时间（毫秒）
     */
    @Builder.Default
    private long recoveryBatchInterval = 1000L;

    /**
     * 备份目录不可用时是否阻止启动
     * true=阻止启动，false=仅记录警告（默认false）
     */
    @Builder.Default
    private boolean failOnBackupDirMissing = false;
}