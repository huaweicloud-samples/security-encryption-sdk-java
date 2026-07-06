package com.huaweicloud.encryptionsdk.log;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class LogFileBackup {

    private static final Logger LOGGER = LoggerFactory.getLogger(LogFileBackup.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private static final String DEFAULT_BACKUP_DIR = "lts_log_backup";
    private static final String BACKUP_FILE_PREFIX = "lts_backup_";
    private static final String BACKUP_FILE_SUFFIX = ".json";
    private static final long MAX_BACKUP_FILE_SIZE = 10 * 1024 * 1024;

    private final String backupDirPath;
    private final boolean failOnMissing;

    public LogFileBackup() {
        this(System.getProperty("user.home") + File.separator + DEFAULT_BACKUP_DIR, false);
    }

    public LogFileBackup(String backupDirPath) {
        this(backupDirPath, false);
    }

    public LogFileBackup(String backupDirPath, boolean failOnMissing) {
        if (backupDirPath == null || backupDirPath.trim().isEmpty()) {
            throw new IllegalArgumentException("Backup directory path cannot be null or empty");
        }

        this.backupDirPath = backupDirPath.trim();
        this.failOnMissing = failOnMissing;

        initBackupDir();
    }

    private void initBackupDir() {
        File backupDir = new File(backupDirPath);

        if (backupDir.exists()) {
            if (!backupDir.isDirectory()) {
                if (failOnMissing) {
                    throw new HuaweicloudException("Backup path exists but is not a directory: " + backupDirPath);
                }
                LOGGER.error("Backup path exists but is not a directory: {}", backupDirPath);
                return;
            }

            if (!backupDir.canWrite()) {
                if (failOnMissing) {
                    throw new HuaweicloudException("No write permission for backup directory: " + backupDirPath);
                }
                LOGGER.error("No write permission for backup directory: {}", backupDirPath);
                return;
            }

            File testFile = new File(backupDir, ".write_test_" + System.currentTimeMillis());
            try {
                if (!testFile.createNewFile()) {
                    if (failOnMissing) {
                        throw new HuaweicloudException("Cannot create test file in backup directory: " + backupDirPath);
                    }
                    LOGGER.error("Cannot create test file in backup directory: {}", backupDirPath);
                    return;
                }
                testFile.delete();
            } catch (IOException e) {
                if (failOnMissing) {
                    throw new HuaweicloudException("Cannot write to backup directory: " + backupDirPath, e);
                }
                LOGGER.error("Cannot write to backup directory: {}", backupDirPath, e);
                return;
            }

            LOGGER.debug("Backup directory is writable: {}", backupDirPath);
        } else {
            boolean created = backupDir.mkdirs();
            if (!created) {
                if (failOnMissing) {
                    throw new HuaweicloudException("Failed to create backup directory: " + backupDirPath);
                }
                LOGGER.warn("Failed to create backup directory: {}. Backup functionality will be disabled.", backupDirPath);
                return;
            }

            LOGGER.info("Created backup directory: {}", backupDirPath);
        }
    }

    public String saveFailedLogs(List<String> failedLogs, long timestamp) {
        if (failedLogs == null || failedLogs.isEmpty()) {
            LOGGER.debug("No failed logs to save");
            return null;
        }

        try {
            String fileName = BACKUP_FILE_PREFIX + timestamp + BACKUP_FILE_SUFFIX;
            File backupFile = new File(backupDirPath, fileName);

            String jsonContent = OBJECT_MAPPER.writeValueAsString(failedLogs);

            Files.write(backupFile.toPath(), jsonContent.getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);

            LOGGER.info("Saved {} failed logs to: {}", failedLogs.size(), backupFile.getAbsolutePath());
            return backupFile.getCanonicalPath();

        } catch (IOException e) {
            LOGGER.error("Failed to save {} failed logs to backup file: {}",
                failedLogs.size(), backupDirPath, e);
            return null;

        } catch (Exception e) {
            LOGGER.error("Unexpected error when saving failed logs", e);
            return null;
        }
    }

    public List<String> recoverFailedLogs() {
        List<String> recoveredLogs = new ArrayList<>();

        try {
            File backupDir = new File(backupDirPath);
            if (!backupDir.exists() || !backupDir.isDirectory()) {
                LOGGER.info("Backup directory does not exist: {}", backupDirPath);
                return recoveredLogs;
            }

            File[] backupFiles = backupDir.listFiles((dir, name) ->
                name.startsWith(BACKUP_FILE_PREFIX) && name.endsWith(BACKUP_FILE_SUFFIX));

            if (backupFiles == null || backupFiles.length == 0) {
                LOGGER.info("No backup files found in: {}", backupDirPath);
                return recoveredLogs;
            }

            Arrays.sort(backupFiles, (f1, f2) -> {
                long t1 = extractTimestampFromFile(f1.getName());
                long t2 = extractTimestampFromFile(f2.getName());
                return Long.compare(t1, t2);
            });

            for (File backupFile : backupFiles) {
                try {
                    if (backupFile.length() > MAX_BACKUP_FILE_SIZE) {
                        LOGGER.warn("Backup file too large ({} bytes), skipping: {}",
                            backupFile.length(), backupFile.getAbsolutePath());
                        continue;
                    }

                    String content = new String(Files.readAllBytes(backupFile.toPath()),
                        StandardCharsets.UTF_8);

                    List<String> logs = OBJECT_MAPPER.readValue(content,
                        new TypeReference<ArrayList<String>>() {});

                    if (logs != null && !logs.isEmpty()) {
                        recoveredLogs.addAll(logs);
                        LOGGER.info("Recovered {} logs from: {}", logs.size(), backupFile.getAbsolutePath());

                        if (backupFile.delete()) {
                            LOGGER.info("  -> Deleted backup file: {}", backupFile.getAbsolutePath());
                        } else {
                            LOGGER.warn("  -> Failed to delete backup file: {}", backupFile.getAbsolutePath());
                        }
                    }

                } catch (Exception e) {
                    LOGGER.error("Failed to recover logs from: {}", backupFile.getAbsolutePath(), e);
                }
            }

            LOGGER.info("Total recovered {} failed logs from {}", recoveredLogs.size(), backupDirPath);
            return recoveredLogs;

        } catch (Exception e) {
            LOGGER.error("Failed to recover failed logs from: {}", backupDirPath, e);
            return recoveredLogs;
        }
    }

    private long extractTimestampFromFile(String fileName) {
        try {
            String timestampStr = fileName.substring(
                BACKUP_FILE_PREFIX.length(),
                fileName.length() - BACKUP_FILE_SUFFIX.length()
            );
            return Long.parseLong(timestampStr);
        } catch (Exception e) {
            LOGGER.warn("Failed to extract timestamp from file name: {}", fileName, e);
            return 0;
        }
    }

    public void clearAllBackupFiles() {
        File backupDir = new File(backupDirPath);
        if (!backupDir.exists()) {
            return;
        }

        File[] backupFiles = backupDir.listFiles((dir, name) ->
            name.startsWith(BACKUP_FILE_PREFIX) && name.endsWith(BACKUP_FILE_SUFFIX));

        if (backupFiles != null) {
            for (File backupFile : backupFiles) {
                if (backupFile.delete()) {
                    LOGGER.info("Deleted backup file: {}", backupFile.getAbsolutePath());
                }
            }
        }
    }

    public String getBackupDirPath() {
        return backupDirPath;
    }
}
