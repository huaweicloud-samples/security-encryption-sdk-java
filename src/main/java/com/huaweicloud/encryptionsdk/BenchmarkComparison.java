package com.huaweicloud.encryptionsdk;

import com.huaweicloud.encryptionsdk.keyrings.KmsKeyringFactory;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Properties;

/**
 * Java SDK 性能基准测试
 * 对比：本地 AES-256-CBC vs SDK AES-256-GCM vs SDK SM4-128-GCM
 * 测试 1GB 文件的加解密性能
 */
public class BenchmarkComparison {

    // KMS 配置（从 config.properties 读取）
    private static String AK;
    private static String SK;
    private static String PROJECT_ID;
    private static String REGION;
    private static String KEY_ID;
    private static String ENDPOINT;
    private static String BENCHMARK_DIR;

    // 测试参数
    private static final int TEST_SIZE_MB = 1024; // 1GB
    private static final int ROUNDS = 2;
    private static final int CHUNK_SIZE = 64 * 1024; // 64KB

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: java -cp encryption-sdk.jar com.huaweicloud.encryptionsdk.BenchmarkComparison <config.properties>");
            System.exit(1);
        }

        // 加载配置
        loadConfig(args[0]);

        System.out.println("=".repeat(70));
        System.out.println("Java SDK 性能对比测试 - " + TEST_SIZE_MB + "MB 文件");
        System.out.println("对比：本地 AES-256-CBC vs SDK AES-256-GCM vs SDK SM4-128-GCM");
        System.out.println("=".repeat(70));

        // 创建临时测试文件
        // 测试文件目录（从配置读取，默认当前工作目录）
        Path testDir = Paths.get(BENCHMARK_DIR);
        Files.createDirectories(testDir);
        Path testFile = testDir.resolve("test_" + TEST_SIZE_MB + "mb.bin");

        System.out.println("\n[阶段] 生成 " + TEST_SIZE_MB + "MB 测试文件...");
        generateTestFile(testFile, TEST_SIZE_MB);
        System.out.println("文件就绪: " + testFile);

        try {
            // 1. 测试本地 AES-256-CBC
            System.out.println("\n--- 本地 AES-256-CBC ---");
            LocalAESCipher localCipher = new LocalAESCipher();
            benchmarkFileEncryption("本地 AES-256-CBC", localCipher, testFile, ROUNDS);

            // 2. 测试 SDK AES-256-GCM
            System.out.println("\n--- SDK AES-256-GCM ---");
            SdkWrapper sdkAes = createSdkWrapper(CryptoAlgorithm.AES_256_GCM_NOPADDING);
            benchmarkFileEncryption("SDK AES-256-GCM", sdkAes, testFile, ROUNDS);

            // 3. 测试 SDK SM4-128-GCM
            System.out.println("\n--- SDK SM4-128-GCM ---");
            SdkWrapper sdkSm4 = createSdkWrapper(CryptoAlgorithm.SM4_128_GCM_NOPADDING);
            benchmarkFileEncryption("SDK SM4-128-GCM", sdkSm4, testFile, ROUNDS);

        } finally {
            // 保留测试文件，方便复用，不清理
            System.out.println("\n[清理] 测试文件保留在: " + testDir);
        }

        System.out.println("\n" + "=".repeat(70));
        System.out.println("测试完成！");
        System.out.println("=".repeat(70));
    }

    private static void loadConfig(String configPath) throws Exception {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(configPath)) {
            props.load(fis);
        }

        AK = props.getProperty("ak");
        SK = props.getProperty("sk");
        PROJECT_ID = props.getProperty("kms.projectId");
        REGION = props.getProperty("kms.region");
        KEY_ID = props.getProperty("kms.keyId");
        ENDPOINT = props.getProperty("kms.endpoint");
        BENCHMARK_DIR = props.getProperty("benchmark.dir", System.getProperty("user.dir"));

        if (AK == null || SK == null || PROJECT_ID == null || REGION == null || KEY_ID == null) {
            throw new IllegalArgumentException("Missing required KMS configuration in " + configPath);
        }

        System.out.println("[配置] KMS Region: " + REGION);
        System.out.println("[配置] KMS KeyId: " + KEY_ID);
        System.out.println("[配置] KMS Endpoint: " + (ENDPOINT != null ? ENDPOINT : "default"));
        System.out.println("[配置] Benchmark Dir: " + BENCHMARK_DIR);
    }

    private static SdkWrapper createSdkWrapper(CryptoAlgorithm algorithm) {
        KMSConfig kmsConfig = new KMSConfig(REGION, KEY_ID, PROJECT_ID, ENDPOINT);

        HuaweiConfig config = HuaweiConfig.builder()
                .ak(AK)
                .sk(SK)
                .kmsConfigList(Collections.singletonList(kmsConfig))
                .cryptoAlgorithm(algorithm)
                .isDiscovery(true)
                .build();

        KMSKeyring keyring = new KmsKeyringFactory().getKeyring(KeyringTypeEnum.KMS_MULTI_REGION.getType());

        HuaweiCrypto huaweiCrypto = new HuaweiCrypto(config).withKeyring(keyring);

        return new SdkWrapper(huaweiCrypto, algorithm);
    }

    private static void generateTestFile(Path path, int sizeMb) throws IOException {
        byte[] buffer = new byte[4 * 1024 * 1024]; // 4MB
        SecureRandom random = new SecureRandom();

        try (FileOutputStream fos = new FileOutputStream(path.toFile())) {
            int remaining = sizeMb;
            while (remaining > 0) {
                int toWrite = Math.min(4, remaining);
                random.nextBytes(buffer);
                fos.write(buffer, 0, toWrite * 1024 * 1024);
                remaining -= toWrite;
            }
        }
    }

    private static void benchmarkFileEncryption(String label, EncryptionHandler handler, Path testFile, int rounds) throws Exception {
        Path testDir = Paths.get(BENCHMARK_DIR);
        Files.createDirectories(testDir);
        String safeLabel = label.replaceAll("\\s+", "_");
        Path encFile = testDir.resolve(safeLabel + "_encrypted.bin");
        Path decFile = testDir.resolve(safeLabel + "_decrypted.bin");

        long fileSize = Files.size(testFile);
        double fileSizeMb = fileSize / (1024.0 * 1024.0);

        long[] encTimes = new long[rounds];
        long[] decTimes = new long[rounds];

        for (int i = 0; i < rounds; i++) {
            // 加密
            long startEnc = System.nanoTime();
            handler.encryptFile(testFile, encFile);
            long endEnc = System.nanoTime();
            encTimes[i] = endEnc - startEnc;

            // 解密
            long startDec = System.nanoTime();
            handler.decryptFile(encFile, decFile);
            long endDec = System.nanoTime();
            decTimes[i] = endDec - startDec;

            double encSec = encTimes[i] / 1_000_000_000.0;
            double decSec = decTimes[i] / 1_000_000_000.0;
            System.out.printf("  [%d/%d] 加密=%.2fs  解密=%.2fs%n", i + 1, rounds, encSec, decSec);

            // 清理本轮文件
            Files.deleteIfExists(encFile);
            Files.deleteIfExists(decFile);
        }

        // 计算统计
        long avgEncNs = average(encTimes);
        long avgDecNs = average(decTimes);
        long minEncNs = min(encTimes);
        long minDecNs = min(decTimes);
        long maxEncNs = max(encTimes);
        long maxDecNs = max(decTimes);

        double avgEncSec = avgEncNs / 1_000_000_000.0;
        double avgDecSec = avgDecNs / 1_000_000_000.0;
        double minEncSec = minEncNs / 1_000_000_000.0;
        double minDecSec = minDecNs / 1_000_000_000.0;
        double maxEncSec = maxEncNs / 1_000_000_000.0;
        double maxDecSec = maxDecNs / 1_000_000_000.0;

        double encThroughput = fileSizeMb / avgEncSec;
        double decThroughput = fileSizeMb / avgDecSec;

        System.out.println("\n" + "=".repeat(70));
        System.out.println(label + " - 文件加解密测试");
        System.out.println("文件大小: " + String.format("%.1f", fileSizeMb) + " MB | 轮次: " + rounds);
        System.out.println("=".repeat(70));
        System.out.printf("加密  avg=%.2fs  min=%.2fs  max=%.2fs%n", avgEncSec, minEncSec, maxEncSec);
        System.out.printf("解密  avg=%.2fs  min=%.2fs  max=%.2fs%n", avgDecSec, minDecSec, maxDecSec);
        System.out.printf("加密吞吐: %.1f MB/s%n", encThroughput);
        System.out.printf("解密吞吐: %.1f MB/s%n", decThroughput);
        System.out.println("=".repeat(70) + "\n");

        // 清理本轮输出文件（测试源文件保留）
        Files.deleteIfExists(encFile);
        Files.deleteIfExists(decFile);
    }

    private static long average(long[] values) {
        long sum = 0;
        for (long v : values) {
            sum += v;
        }
        return sum / values.length;
    }

    private static long min(long[] values) {
        long min = values[0];
        for (long v : values) {
            if (v < min) min = v;
        }
        return min;
    }

    private static long max(long[] values) {
        long max = values[0];
        for (long v : values) {
            if (v > max) max = v;
        }
        return max;
    }

    private static void deleteDirectory(File dir) {
        if (dir.isDirectory()) {
            File[] files = dir.listFiles();
            if (files != null) {
                for (File file : files) {
                    deleteDirectory(file);
                }
            }
        }
        dir.delete();
    }

    // 加密处理接口
    interface EncryptionHandler {
        void encryptFile(Path input, Path output) throws Exception;
        void decryptFile(Path input, Path output) throws Exception;
    }

    // 本地 AES-256-CBC 实现
    static class LocalAESCipher implements EncryptionHandler {
        private final SecretKey secretKey;
        private final SecureRandom random = new SecureRandom();

        public LocalAESCipher() throws Exception {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            this.secretKey = keyGen.generateKey();
        }

        @Override
        public void encryptFile(Path input, Path output) throws Exception {
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            try (FileInputStream fis = new FileInputStream(input.toFile());
                 FileOutputStream fos = new FileOutputStream(output.toFile())) {

                // 写入 IV
                fos.write(iv);

                // 分块加密
                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    byte[] encrypted = cipher.update(buffer, 0, bytesRead);
                    if (encrypted != null) {
                        fos.write(encrypted);
                    }
                }
                byte[] finalBlock = cipher.doFinal();
                if (finalBlock != null) {
                    fos.write(finalBlock);
                }
            }
        }

        @Override
        public void decryptFile(Path input, Path output) throws Exception {
            try (FileInputStream fis = new FileInputStream(input.toFile());
                 FileOutputStream fos = new FileOutputStream(output.toFile())) {

                // 读取 IV
                byte[] iv = new byte[16];
                fis.read(iv);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

                // 分块解密
                byte[] buffer = new byte[CHUNK_SIZE];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    byte[] decrypted = cipher.update(buffer, 0, bytesRead);
                    if (decrypted != null) {
                        fos.write(decrypted);
                    }
                }
                byte[] finalBlock = cipher.doFinal();
                if (finalBlock != null) {
                    fos.write(finalBlock);
                }
            }
        }
    }

    // SDK 封装
    static class SdkWrapper implements EncryptionHandler {
        private final HuaweiCrypto huaweiCrypto;
        private final CryptoAlgorithm algorithm;

        public SdkWrapper(HuaweiCrypto huaweiCrypto, CryptoAlgorithm algorithm) {
            this.huaweiCrypto = huaweiCrypto;
            this.algorithm = algorithm;
        }

        @Override
        public void encryptFile(Path input, Path output) throws Exception {
            huaweiCrypto.encrypt(input.toString(), output.toString(), null);
        }

        @Override
        public void decryptFile(Path input, Path output) throws Exception {
            huaweiCrypto.decrypt(input.toString(), output.toString());
        }
    }
}
