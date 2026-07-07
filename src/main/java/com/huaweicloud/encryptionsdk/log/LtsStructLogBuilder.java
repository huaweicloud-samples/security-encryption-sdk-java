package com.huaweicloud.encryptionsdk.log;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * LTS结构化日志构建器，负责将加解密操作参数组装为JSON格式日志。
 */
public class LtsStructLogBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(LtsStructLogBuilder.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    private static final Pattern CONTROL_CHARS_PATTERN = Pattern.compile("[\\r\\n\\t\\u0000-\\u001F\\u007F-\\u009F]");

    /**
     * 构建加密操作结构化日志
     */
    public static String buildEncryptStructLog(
        String encryptFileName,
        Long encryptDataBytes,
        String encryptOutputFileName,
        Long encryptOutputBytes,
        String keyId,
        String accessPointType,
        String instanceId
    ) {
        return buildStructLog("encrypt", encryptFileName, encryptDataBytes,
            encryptOutputFileName, encryptOutputBytes,
            keyId, accessPointType, instanceId);
    }

    /**
     * 构建解密操作结构化日志
     */
    public static String buildDecryptStructLog(
        String decryptFileName,
        Long decryptDataBytes,
        String decryptOutputFileName,
        Long decryptOutputBytes,
        String keyId,
        String accessPointType,
        String instanceId
    ) {
        return buildStructLog("decrypt", decryptFileName, decryptDataBytes,
            decryptOutputFileName, decryptOutputBytes,
            keyId, accessPointType, instanceId);
    }

    /**
     * 构建结构化日志的公共方法
     *
     * @param operation       操作类型（encrypt/decrypt）
     * @param fileName        输入文件名
     * @param dataBytes       输入数据字节数
     * @param outputFileName  输出文件名
     * @param outputBytes     输出数据字节数
     * @param keyId           密钥ID
     * @param accessPointType 接入点类型
     * @param instanceId      实例ID
     * @return JSON格式的结构化日志字符串
     */
    public static String buildStructLog(
        String operation,
        String fileName,
        Long dataBytes,
        String outputFileName,
        Long outputBytes,
        String keyId,
        String accessPointType,
        String instanceId
    ) {
        Map<String, String> structLog = new LinkedHashMap<>();
        long ts = System.currentTimeMillis();
        structLog.put("timestamp", String.valueOf(ts));
        structLog.put("utcTime", Instant.ofEpochMilli(ts).atZone(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT));
        structLog.put("operation", sanitize(operation));

        String fieldPrefix = operation;
        if (fileName != null && !fileName.isEmpty()) {
            structLog.put(fieldPrefix + "FileName", sanitize(fileName));
        }
        if (dataBytes != null && dataBytes > 0) {
            structLog.put(fieldPrefix + "DataBytes", String.valueOf(dataBytes));
        }
        if (outputFileName != null && !outputFileName.isEmpty()) {
            structLog.put(fieldPrefix + "OutputFileName", sanitize(outputFileName));
        }
        if (outputBytes != null && outputBytes > 0) {
            structLog.put(fieldPrefix + "OutputBytes", String.valueOf(outputBytes));
        }
        if (keyId != null && !keyId.isEmpty()) {
            structLog.put("keyId", sanitize(keyId));
        }
        if (accessPointType != null && !accessPointType.isEmpty()) {
            structLog.put("accessPointType", sanitize(accessPointType));
        }
        if (instanceId != null && !instanceId.isEmpty()) {
            structLog.put("instanceId", sanitize(instanceId));
        }

        String ip = getLocalIp();
        if (ip != null && !ip.isEmpty()) {
            structLog.put("ipAddress", ip);
        }

        return toJsonString(structLog);
    }

    static String sanitize(String input) {
        if (input == null) {
            return "";
        }
        return CONTROL_CHARS_PATTERN.matcher(input).replaceAll("");
    }

    private static String toJsonString(Map<String, String> map) {
        try {
            return OBJECT_MAPPER.writeValueAsString(map);
        } catch (JsonProcessingException e) {
            LOGGER.error("Failed to serialize log to JSON, returning error placeholder", e);
            return "";
        }
    }

    private static String getLocalIp() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface ni = interfaces.nextElement();
                if (ni.isLoopback() || ni.isVirtual() || !ni.isUp()) {
                    continue;
                }
                Enumeration<InetAddress> addresses = ni.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr.isLoopbackAddress() || addr instanceof Inet6Address) {
                        continue;
                    }
                    return addr.getHostAddress();
                }
            }
        } catch (Exception e) {
            LOGGER.warn("Failed to get local IP address", e);
        }
        return null;
    }
}
