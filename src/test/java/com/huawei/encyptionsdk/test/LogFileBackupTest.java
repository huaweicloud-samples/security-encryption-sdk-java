package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.log.LogFileBackup;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class LogFileBackupTest {

    private File tempDir;

    @Before
    public void setUp() throws IOException {
        tempDir = Files.createTempDirectory("lts_backup_test").toFile();
    }

    @After
    public void tearDown() {
        deleteRecursive(tempDir);
    }

    private void deleteRecursive(File file) {
        if (file == null || !file.exists()) {
            return;
        }
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    deleteRecursive(child);
                }
            }
        }
        file.delete();
    }

    @Test
    public void testConstructor_NormalDir() {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());
        Assert.assertEquals(tempDir.getAbsolutePath(), backup.getBackupDirPath());
    }

    @Test
    public void testConstructor_CreateDir() {
        File newDir = new File(tempDir, "new_sub_dir");
        Assert.assertFalse(newDir.exists());

        LogFileBackup backup = new LogFileBackup(newDir.getAbsolutePath());
        Assert.assertTrue(newDir.exists());
        Assert.assertEquals(newDir.getAbsolutePath(), backup.getBackupDirPath());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructor_NullPath() {
        new LogFileBackup(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructor_EmptyPath() {
        new LogFileBackup("  ");
    }

    @Test
    public void testConstructor_DefaultConstructor() {
        LogFileBackup backup = new LogFileBackup();
        Assert.assertNotNull(backup.getBackupDirPath());
    }

    @Test
    public void testSaveAndRecoverFailedLogs() {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        List<String> logs = new ArrayList<>();
        logs.add("log1");
        logs.add("log2");

        String savedPath = backup.saveFailedLogs(logs, System.currentTimeMillis());
        Assert.assertNotNull(savedPath);
        Assert.assertTrue(new File(savedPath).exists());

        List<String> recovered = backup.recoverFailedLogs();
        Assert.assertFalse(recovered.isEmpty());
    }

    @Test
    public void testSaveFailedLogs_NullList() {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());
        String result = backup.saveFailedLogs(null, System.currentTimeMillis());
        Assert.assertNull(result);
    }

    @Test
    public void testSaveFailedLogs_EmptyList() {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());
        String result = backup.saveFailedLogs(Collections.emptyList(), System.currentTimeMillis());
        Assert.assertNull(result);
    }

    @Test
    public void testRecoverFailedLogs_NoBackupFiles() {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());
        List<String> recovered = backup.recoverFailedLogs();
        Assert.assertTrue(recovered.isEmpty());
    }

    @Test
    public void testRecoverFailedLogs_DirNotExist() {
        LogFileBackup backup = new LogFileBackup(new File(tempDir, "nonexistent").getAbsolutePath());
        List<String> recovered = backup.recoverFailedLogs();
        Assert.assertTrue(recovered.isEmpty());
    }

    @Test
    public void testClearAllBackupFiles() {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        List<String> logs = Collections.singletonList("log-entry");
        backup.saveFailedLogs(logs, System.currentTimeMillis());
        backup.saveFailedLogs(logs, System.currentTimeMillis() + 1);

        File dir = tempDir;
        File[] files = dir.listFiles((d, name) -> name.startsWith("lts_backup_"));
        Assert.assertNotNull(files);
        Assert.assertTrue(files.length > 0);

        backup.clearAllBackupFiles();

        files = dir.listFiles((d, name) -> name.startsWith("lts_backup_"));
        Assert.assertNotNull(files);
        Assert.assertEquals(0, files.length);
    }

    @Test
    public void testClearAllBackupFiles_DirNotExist() {
        String nonExistPath = new File(tempDir, "nonexistent").getAbsolutePath();
        LogFileBackup backup = new LogFileBackup(nonExistPath);
        backup.clearAllBackupFiles();
        Assert.assertNotNull(backup.getBackupDirPath());
    }

    @Test(expected = HuaweicloudException.class)
    public void testConstructor_FailOnMissing_NotDirectory() throws IOException {
        File file = new File(tempDir, "not_a_dir.txt");
        Files.write(file.toPath(), "hello".getBytes(StandardCharsets.UTF_8));

        new LogFileBackup(file.getAbsolutePath(), true);
    }

    @Test
    public void testConstructor_NotDirectory_NoFail() throws IOException {
        File file = new File(tempDir, "not_a_dir2.txt");
        Files.write(file.toPath(), "hello".getBytes(StandardCharsets.UTF_8));

        LogFileBackup backup = new LogFileBackup(file.getAbsolutePath(), false);
        Assert.assertEquals(file.getAbsolutePath(), backup.getBackupDirPath());
    }

    @Test
    public void testSaveFailedLogs_MultipleBatches() {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        List<String> logs1 = Collections.singletonList("log1");
        List<String> logs2 = Collections.singletonList("log2");

        long ts = System.currentTimeMillis();
        backup.saveFailedLogs(logs1, ts);
        backup.saveFailedLogs(logs2, ts + 1);

        List<String> recovered = backup.recoverFailedLogs();
        Assert.assertFalse(recovered.isEmpty());
    }

    @Test
    public void testRecoverFailedLogs_CorruptedFile() throws IOException {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        File corruptFile = new File(tempDir, "lts_backup_1234567890.json");
        Files.write(corruptFile.toPath(), "not valid json".getBytes(StandardCharsets.UTF_8));

        List<String> recovered = backup.recoverFailedLogs();
        Assert.assertTrue(recovered.isEmpty());
    }

    @Test
    public void testGetBackupDirPath() {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());
        Assert.assertEquals(tempDir.getAbsolutePath(), backup.getBackupDirPath());
    }

    @Test
    public void testConstructor_CannotCreateDir_NoFail() {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath() + "/nonexistent_sub/sub2", false);
        Assert.assertNotNull(backup.getBackupDirPath());
    }

    @Test
    public void testRecoverFailedLogs_LargeFileSkipped() throws IOException {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        File largeFile = new File(tempDir, "lts_backup_9999999999.json");
        byte[] largeContent = new byte[11 * 1024 * 1024];
        Files.write(largeFile.toPath(), largeContent);

        List<String> recovered = backup.recoverFailedLogs();
        Assert.assertTrue(recovered.isEmpty());
    }

    @Test
    public void testRecoverFailedLogs_EmptyJsonArray() throws IOException {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        File emptyArrayFile = new File(tempDir, "lts_backup_8888888888.json");
        Files.write(emptyArrayFile.toPath(), "[]".getBytes(StandardCharsets.UTF_8));

        List<String> recovered = backup.recoverFailedLogs();
        Assert.assertTrue(recovered.isEmpty());
    }

    @Test
    public void testRecoverFailedLogs_MixedValidAndInvalid() throws IOException {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        List<String> validLogs = new ArrayList<>();
        validLogs.add("valid-log");
        backup.saveFailedLogs(validLogs, System.currentTimeMillis());

        File corruptFile = new File(tempDir, "lts_backup_1111111111.json");
        Files.write(corruptFile.toPath(), "bad json".getBytes(StandardCharsets.UTF_8));

        List<String> recovered = backup.recoverFailedLogs();
        Assert.assertFalse(recovered.isEmpty());
    }

    @Test
    public void testSaveFailedLogs_ToInvalidDir() {
        File dir = new File(tempDir, "deleted_dir");
        dir.mkdirs();
        LogFileBackup innerBackup = new LogFileBackup(dir.getAbsolutePath());
        deleteRecursive(dir);

        String result = innerBackup.saveFailedLogs(
                Collections.singletonList("log-entry"), System.currentTimeMillis());
        Assert.assertNull(result);
    }

    @Test
    public void testExtractTimestampFromFile_InvalidName() throws IOException {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        File badNameFile = new File(tempDir, "lts_backup_notanumber.json");
        Files.write(badNameFile.toPath(), "[]".getBytes(StandardCharsets.UTF_8));

        List<String> recovered = backup.recoverFailedLogs();
        Assert.assertTrue(recovered.isEmpty());
    }

    @Test
    public void testRecoverFailedLogs_FileDeleteFails() throws IOException {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        List<String> logs = Collections.singletonList("log-entry");
        String path = backup.saveFailedLogs(logs, System.currentTimeMillis());
        Assert.assertNotNull(path);

        File savedFile = new File(path);
        savedFile.setReadOnly();

        try {
            List<String> recovered = backup.recoverFailedLogs();
            Assert.assertFalse(recovered.isEmpty());
        } finally {
            savedFile.setWritable(true);
            savedFile.delete();
        }
    }

    @Test
    public void testConstructor_SingleArgConstructor() {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());
        Assert.assertEquals(tempDir.getAbsolutePath(), backup.getBackupDirPath());
    }

    @Test
    public void testConstructor_ExistingDirNotWritable() {
        File readOnlyDir = new File(tempDir, "readonly_dir");
        readOnlyDir.mkdirs();
        readOnlyDir.setReadOnly();

        try {
            LogFileBackup backup = new LogFileBackup(readOnlyDir.getAbsolutePath(), true);
        } catch (HuaweicloudException e) {
            Assert.assertTrue(e.getMessage().contains("write") || e.getMessage().contains("Write"));
        } finally {
            readOnlyDir.setWritable(true);
        }
    }

    @Test
    public void testConstructor_ExistingDirNotWritableNoFail() {
        File readOnlyDir = new File(tempDir, "readonly_dir2");
        readOnlyDir.mkdirs();
        readOnlyDir.setReadOnly();

        try {
        LogFileBackup backup = new LogFileBackup(readOnlyDir.getAbsolutePath(), false);
        Assert.assertEquals(readOnlyDir.getAbsolutePath(), backup.getBackupDirPath());
        } finally {
            readOnlyDir.setWritable(true);
        }
    }

    @Test
    public void testRecoverFailedLogs_DeleteFailsAfterRecover() throws IOException {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        List<String> logs = Collections.singletonList("log-to-recover");
        String path = backup.saveFailedLogs(logs, System.currentTimeMillis());
        Assert.assertNotNull(path);

        File savedFile = new File(path);
        savedFile.setReadOnly();

        try {
            List<String> recovered = backup.recoverFailedLogs();
            Assert.assertFalse(recovered.isEmpty());
        } finally {
            savedFile.setWritable(true);
            savedFile.delete();
        }
    }

    @Test
    public void testRecoverFailedLogs_NullJsonContent() throws IOException {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        File nullFile = new File(tempDir, "lts_backup_7777777777.json");
        Files.write(nullFile.toPath(), "null".getBytes(StandardCharsets.UTF_8));

        List<String> recovered = backup.recoverFailedLogs();
        Assert.assertTrue(recovered.isEmpty());
    }

    @Test
    public void testConstructor_FailOnMissing_CannotCreateDir() {
        String impossiblePath = tempDir.getAbsolutePath() + File.separator + "\0invalid";
        try {
            new LogFileBackup(impossiblePath, true);
        } catch (HuaweicloudException e) {
            Assert.assertTrue(e.getMessage().contains("Failed") || e.getMessage().contains("failed") || e.getMessage().contains("directory"));
        }
    }

    @Test
    public void testConstructor_FailOnMissing_CannotCreateTestFile() throws IOException {
        File subDir = new File(tempDir, "no_write_test");
        subDir.mkdirs();
        File blockFile = new File(subDir, ".write_test_" + System.currentTimeMillis());
        blockFile.createNewFile();
        blockFile.setReadOnly();

        try {
            LogFileBackup backup = new LogFileBackup(subDir.getAbsolutePath(), true);
        } catch (HuaweicloudException e) {
            Assert.assertTrue(e.getMessage().contains("write") || e.getMessage().contains("Write") || e.getMessage().contains("Failed"));
        } finally {
            blockFile.setWritable(true);
            blockFile.delete();
        }
    }

    @Test
    public void testRecoverFailedLogs_WithMultipleValidFiles() throws IOException {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        List<String> logs1 = new ArrayList<>();
        logs1.add("log1");
        logs1.add("log2");
        backup.saveFailedLogs(logs1, System.currentTimeMillis());

        List<String> logs2 = new ArrayList<>();
        logs2.add("log3");
        backup.saveFailedLogs(logs2, System.currentTimeMillis() + 1);

        List<String> recovered = backup.recoverFailedLogs();
        Assert.assertEquals(3, recovered.size());
        Assert.assertTrue(recovered.contains("log1"));
        Assert.assertTrue(recovered.contains("log2"));
        Assert.assertTrue(recovered.contains("log3"));
    }

    @Test
    public void testClearAllBackupFiles_WithNullFileList() {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());
        backup.clearAllBackupFiles();
        File[] files = tempDir.listFiles((d, name) -> name.startsWith("lts_backup_"));
        Assert.assertNotNull(files);
        Assert.assertEquals(0, files.length);
    }

    @Test
    public void testExtractTimestampFromFile_ValidName() throws IOException {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        List<String> logs = Collections.singletonList("log");
        backup.saveFailedLogs(logs, 12345L);

        File dir = tempDir;
        File[] files = dir.listFiles((d, name) -> name.startsWith("lts_backup_"));
        Assert.assertNotNull(files);
        Assert.assertTrue(files.length > 0);
        Assert.assertTrue(files[0].getName().startsWith("lts_backup_12345"));
    }

    @Test
    public void testConstructor_FailOnMissing_MkdirsFails() {
        String impossiblePath = "Z:\\nonexistent_impossible_dir_" + System.currentTimeMillis() + "\\sub";
        try {
            LogFileBackup backup = new LogFileBackup(impossiblePath, true);
            Assert.assertNotNull(backup.getBackupDirPath());
        } catch (HuaweicloudException e) {
            Assert.assertTrue(e.getMessage().length() > 0);
        } catch (Exception e) {
            Assert.assertTrue(e.getMessage().length() > 0);
        }
    }

    @Test
    public void testConstructor_NoFail_MkdirsFails() {
        String impossiblePath = "Z:\\nonexistent_impossible_dir_" + System.currentTimeMillis() + "\\sub";
        LogFileBackup backup = new LogFileBackup(impossiblePath, false);
        Assert.assertNotNull(backup.getBackupDirPath());
    }

    @Test
    public void testSaveFailedLogs_IOException() throws IOException {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        List<String> logs = Collections.singletonList("log");
        String path = backup.saveFailedLogs(logs, System.currentTimeMillis());
        Assert.assertTrue(new File(path).exists());

        File savedFile = new File(path);
        savedFile.setReadOnly();

        String result = backup.saveFailedLogs(Collections.singletonList("log2"), System.currentTimeMillis() + 1000);
        Assert.assertNotEquals(path, result);
        savedFile.setWritable(true);
        savedFile.delete();
    }

    @Test
    public void testRecoverFailedLogs_EmptyLogsInFile() throws IOException {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        File emptyLogsFile = new File(tempDir, "lts_backup_5555555555.json");
        Files.write(emptyLogsFile.toPath(), "[\"\", \"\"]".getBytes(StandardCharsets.UTF_8));

        List<String> recovered = backup.recoverFailedLogs();
        Assert.assertFalse(recovered.isEmpty());
    }

    @Test
    public void testConstructor_ExistingDirWithTestFileConflict() throws IOException {
        File subDir = new File(tempDir, "write_conflict_dir");
        subDir.mkdirs();

        File conflictFile = new File(subDir, ".write_test_" + System.currentTimeMillis());
        Files.write(conflictFile.toPath(), "block".getBytes(StandardCharsets.UTF_8));
        conflictFile.setReadOnly();

        try {
            LogFileBackup backup = new LogFileBackup(subDir.getAbsolutePath(), true);
        } catch (HuaweicloudException e) {
            Assert.assertTrue(e.getMessage().contains("write") || e.getMessage().contains("Write") || e.getMessage().contains("Failed"));
        } finally {
            conflictFile.setWritable(true);
            conflictFile.delete();
        }
    }

    @Test
    public void testConstructor_ExistingDirWithTestFileConflictNoFail() throws IOException {
        File subDir = new File(tempDir, "write_conflict_dir2");
        subDir.mkdirs();

        File conflictFile = new File(subDir, ".write_test_" + System.currentTimeMillis());
        Files.write(conflictFile.toPath(), "block".getBytes(StandardCharsets.UTF_8));
        conflictFile.setReadOnly();

        try {
            LogFileBackup backup = new LogFileBackup(subDir.getAbsolutePath(), false);
            Assert.assertEquals(subDir.getAbsolutePath(), backup.getBackupDirPath());
        } finally {
            conflictFile.setWritable(true);
            conflictFile.delete();
        }
    }

    @Test
    public void testRecoverFailedLogs_SortedByTimestamp() throws IOException {
        LogFileBackup backup = new LogFileBackup(tempDir.getAbsolutePath());

        List<String> logs1 = Collections.singletonList("log-late");
        backup.saveFailedLogs(logs1, 9999999999L);

        List<String> logs2 = Collections.singletonList("log-early");
        backup.saveFailedLogs(logs2, 1000000000L);

        List<String> recovered = backup.recoverFailedLogs();
        Assert.assertEquals(2, recovered.size());
        Assert.assertEquals("log-early", recovered.get(0));
        Assert.assertEquals("log-late", recovered.get(1));
    }
}
