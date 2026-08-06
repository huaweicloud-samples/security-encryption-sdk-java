package com.huaweicloud.encryptionsdk.log;

import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.lts.appender.JavaSDKAppender;
import com.huaweicloud.lts.producer.Callback;
import com.huaweicloud.lts.producer.Producer;
import com.huaweicloud.lts.producer.Result;
import com.huaweicloud.lts.producer.exception.ProducerException;
import com.huaweicloud.lts.producer.model.log.LogContent;
import com.huaweicloud.lts.producer.model.log.LogItem;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

public class LTSSDKProducer {

    private static final Logger LOGGER = LoggerFactory.getLogger(LTSSDKProducer.class);

    private static final String LABELS_JSON = "{\"source\":\"EncryptionSDK_JAVA\"}";

    private static final Pattern CONTROL_CHARS_PATTERN = Pattern.compile("[\\r\\n\\t\\u0000-\\u001F\\u007F-\\u009F]");

    private final Producer producer;
    private final LogConfig logConfig;
    private final LogFileBackup logFileBackup;
    private volatile boolean initialized = false;
    private LogMetrics metrics = LogMetrics.builder().build();

    private String logGroupId;
    private String logStreamId;
    private boolean useNameForSend;

    public LTSSDKProducer(String ak, String sk, String securityToken, String projectId, String region, LogConfig logConfig) {
        this.logConfig = logConfig;
        this.logFileBackup = new LogFileBackup(logConfig.getBackupDir(), logConfig.isFailOnBackupDirMissing());

        this.logGroupId = logConfig.getLogGroupId();
        this.logStreamId = logConfig.getLogStreamId();
        this.useNameForSend = Utils.isEmpty(this.logGroupId) || Utils.isEmpty(this.logStreamId);

        if (useNameForSend) {
            this.logGroupId = logConfig.getLogGroupName();
            this.logStreamId = logConfig.getLogStreamName();
            LOGGER.info("Using logGroupName/logStreamName for send: {}, {}", this.logGroupId, this.logStreamId);
        } else {
            LOGGER.info("Using logGroupId/logStreamId for send: {}, {}", this.logGroupId, this.logStreamId);
        }

        this.producer = createProducer(ak, sk, securityToken, projectId, region, logConfig);

        this.initialized = true;

        recoverFailedLogsOnStartup();
    }

    private Producer createProducer(String ak, String sk, String securityToken, String projectId, String region, LogConfig config) {
        JavaSDKAppender.Builder builder = JavaSDKAppender.custom()
            .setProjectId(projectId)
            .setAccessKeyId(ak)
            .setAccessKeySecret(sk)
            .setRegionName(region)

            .setTotalSizeInBytes(config.getTotalSizeInBytes())
            .setMaxBlockMs(config.getMaxBlockMs())

            .setBatchCountThreshold(config.getBatchCountThreshold())
            .setBatchSizeThresholdInBytes(config.getBatchSizeThresholdInBytes())
            .setLingerMs(config.getLingerMs())

            .setIoThreadCount(config.getIoThreadCount())

            .setRetries(config.getRetries())
            .setBaseRetryBackoffMs(config.getBaseRetryBackoffMs())
            .setMaxRetryBackoffMs(config.getMaxRetryBackoffMs())

            .setEnableLocalTest(config.isEnableLocalTest())

            .setLogGroupStreamByName(useNameForSend);
        if (StringUtils.isNotEmpty(securityToken)) {
            builder.setSecurityToken(securityToken);
        }
        JavaSDKAppender appender = builder.builder();

        LOGGER.info("LTS Producer created with config:");
        LOGGER.info("  logGroupId: {}", this.logGroupId);
        LOGGER.info("  logStreamId: {}", this.logStreamId);
        LOGGER.info("  useNameForSend: {}", this.useNameForSend);
        LOGGER.info("  batchCountThreshold: {}", config.getBatchCountThreshold());
        LOGGER.info("  lingerMs: {}", config.getLingerMs());
        LOGGER.info("  ioThreadCount: {}", config.getIoThreadCount());
        LOGGER.info("  backupDir: {}", config.getBackupDir());

        return appender.getProducer();
    }

    public void sendLog(String logContent) {
        if (!initialized) {
            LOGGER.warn("LTSSDKProducer is not initialized yet");
            return;
        }

        String sanitized = sanitize(logContent);
        try {
            LogItem logItem = new LogItem();
            LogContent content = new LogContent(System.currentTimeMillis() * 1_000_000, sanitized);
            logItem.setContents(Collections.singletonList(content));
            logItem.setLabels(LABELS_JSON);

            producer.send(
                logGroupId,
                logStreamId,
                useNameForSend,
                Collections.singletonList(logItem),
                new Callback() {
                    @Override
                    public void onCompletion(Result result) {
                        handleCallback(result, Collections.singletonList(sanitized));
                    }
                }
            );

            metrics.addBufferLogCount(1);
            LOGGER.debug("Sent log to buffer, buffer count: {}", metrics.getBufferLogCount());

        } catch (Exception e) {
            LOGGER.error("Failed to send log to LTS", e);
            handleException(e, Collections.singletonList(sanitized));
        }
    }

    public void sendBatchLog(List<String> logContents) {
        if (!initialized || logContents == null || logContents.isEmpty()) {
            LOGGER.error("Invalid batch logs input");
            return;
        }

        List<String> sanitizedLogs = new ArrayList<>(logContents.size());
        List<LogContent> contents = new ArrayList<>(logContents.size());
        long timestamp = System.currentTimeMillis() * 1_000_000;
        for (String log : logContents) {
            String sanitized = sanitize(log);
            sanitizedLogs.add(sanitized);
            contents.add(new LogContent(timestamp, sanitized));
        }

        try {
            LogItem logItem = new LogItem();
            logItem.setContents(contents);
            logItem.setLabels(LABELS_JSON);

            producer.send(
                logGroupId,
                logStreamId,
                useNameForSend,
                Collections.singletonList(logItem),
                new Callback() {
                    @Override
                    public void onCompletion(Result result) {
                        handleCallback(result, sanitizedLogs);
                    }
                }
            );

            metrics.addBufferLogCount(sanitizedLogs.size());
            LOGGER.debug("Sent batch {} logs to buffer, total buffer count: {}",
                sanitizedLogs.size(), metrics.getBufferLogCount());

        } catch (Exception e) {
            LOGGER.error("Failed to send batch logs to LTS", e);
            handleException(e, sanitizedLogs);
        }
    }

    private void handleCallback(Result result, List<String> logs) {
        if (result.isSuccessful()) {
            handleSuccess(logs);
        } else {
            String errorMessage = String.format("ErrorCode: %s, ErrorMessage: %s",
                result.getErrorCode(), result.getErrorMessage());
            handleFailure(logs, errorMessage);
        }
    }

    private void handleSuccess(List<String> logs) {
        metrics.setLastReportTime(System.currentTimeMillis());
        metrics.incrementSuccessCount();
        metrics.addSuccessLogCount(logs.size());
        metrics.addBufferLogCount(-logs.size());
        LOGGER.info("Log report success: {} logs, buffer count: {}, total success: {}",
            logs.size(), metrics.getBufferLogCount(), metrics.getSuccessCount());
    }

    private void handleFailure(List<String> logs, String errorMessage) {
        metrics.incrementFailureCount();
        metrics.addFailureLogCount(logs.size());
        metrics.setLastErrorMessage(errorMessage);
        metrics.setLastErrorTime(System.currentTimeMillis());

        LOGGER.warn("Log report failed: {} logs, error: {}, total failure: {}",
            logs.size(), errorMessage, metrics.getFailureCount());

        String backupFilePath = logFileBackup.saveFailedLogs(logs, System.currentTimeMillis());
        if (backupFilePath != null) {
            LOGGER.info("  -> Failed logs backed up to: {}", backupFilePath);
            LOGGER.info("  -> Will retry on next startup");
        }
    }

    private void handleException(Exception e, List<String> logs) {
        String errorMessage = sanitize(e.getMessage());

        metrics.incrementFailureCount();
        metrics.addFailureLogCount(logs.size());
        metrics.setLastErrorMessage(errorMessage);
        metrics.setLastErrorTime(System.currentTimeMillis());

        LOGGER.warn("Log report exception: {} logs, error: {}", logs.size(), errorMessage, e);

        String backupFilePath = logFileBackup.saveFailedLogs(logs, System.currentTimeMillis());
        if (backupFilePath != null) {
            LOGGER.info("  -> Failed logs backed up to: {}", backupFilePath);
            LOGGER.info("  -> Will retry on next startup");
        }
    }

    private void recoverFailedLogsOnStartup() {
        if (!logConfig.isEnableRecoveryOnStartup()) {
            LOGGER.info("Recovery on startup is disabled");
            return;
        }

        LOGGER.info("=== Recovering failed logs on startup ===");
        List<String> recoveredLogs = logFileBackup.recoverFailedLogs();

        if (!recoveredLogs.isEmpty()) {
            LOGGER.info("Found {} failed logs from backup, using batch recovery...", recoveredLogs.size());

            int batchSize = Math.max(1, logConfig.getRecoveryBatchSize());
            long batchInterval = logConfig.getRecoveryBatchInterval();
            int totalBatches = (int) Math.ceil((double) recoveredLogs.size() / batchSize);

            for (int i = 0; i < recoveredLogs.size(); i += batchSize) {
                int end = Math.min(i + batchSize, recoveredLogs.size());
                List<String> batch = recoveredLogs.subList(i, end);
                int batchNum = (i / batchSize) + 1;

                LOGGER.info("Recovering batch {}/{}, {} logs", batchNum, totalBatches, batch.size());

                sendBatchLog(batch);

                if (end < recoveredLogs.size()) {
                    try {
                        Thread.sleep(batchInterval);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        LOGGER.warn("Recovery interrupted during batch {}", batchNum);
                        break;
                    }
                }
            }

            LOGGER.info("=== Recovery completed ===");
            LOGGER.info("Total logs: {}", recoveredLogs.size());
            LOGGER.info("Total batches: {}", totalBatches);
            LOGGER.info("Batch size: {}", batchSize);
            LOGGER.info("Batch interval: {}ms", batchInterval);
        } else {
            LOGGER.info("No failed logs to recover");
        }
    }

    public LogMetrics getMetrics() {
        return metrics;
    }

    public void resetMetrics() {
        metrics.reset();
    }

    public void close() {
        if (!initialized) {
            return;
        }

        try {
            producer.close();
            LOGGER.info("LTSSDKProducer closed successfully");
        } catch (ProducerException | InterruptedException e) {
            LOGGER.error("Failed to close LTSSDKProducer", e);
        } finally {
            initialized = false;
        }
    }

    public Producer getProducer() {
        return producer;
    }

    public static String sanitize(String input) {
        if (input == null) {
            return "";
        }
        return CONTROL_CHARS_PATTERN.matcher(input).replaceAll("");
    }
}
