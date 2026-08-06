package com.huaweicloud.encryptionsdk.handler;

import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.model.CipherHeader;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Map;

/**
 * @description: 文件解密处理器
 */
public class FileDecryptHandler {

    private int mode;

    private CryptoAlgorithm algorithm;

    private SecretKey secretKey;

    /**
     * 未解析的byte数组
     */
    private byte[] unParsedByte;

    private CipherHeader header;

    public FileDecryptHandler(CryptoAlgorithm algorithm, SecretKey secretKey, int mode) {
        this.mode = mode;
        this.algorithm = algorithm;
        this.secretKey = secretKey;
        this.unParsedByte = new byte[0];
    }

    /**
     * @return void
     * @Description ：数据流解密操作
     * 由于每次读取密文长度固定为blockSize，该数据块长度不一定是实际密文长度，
     * 可能会超过当前解密长度，也可能短于实际解密所需长度，故需对长度进行处理。
     * 使用unParsedByte对多余的字节进行临时保存，等下次循环解密时再进行数据拼接
     * cipherHeader中存储了当前加密文段的iv和密文长度，密文长度根据存储的contentLength确定
     * @Param [inputStream, outputStream, encryptionContext, blockSize]
     * inputStream：密文输入流
     * outputStream：明文输出流
     * encryptionContext：加密上下文
     * blockSize：每次读取流中数据块大小
     **/
    public void processByte(InputStream inputStream, OutputStream outputStream, Map<String, String> encryptionContext,
        int blockSize) throws IOException {
        try {
            byte[] readBytes = new byte[blockSize];
            int readLen = 0;
            CipherHandler cipherHandler = new CipherHandler(algorithm, secretKey, mode);
            byte[] serializedContext = Utils.serializeContext(encryptionContext);
            int fileHeaderLength = new CipherHeader().getFileHeaderLength(algorithm);

            // 复用 CipherHeader 对象，避免每次循环创建新对象
            CipherHeader tempHeader = new CipherHeader();

            while ((readLen = inputStream.read(readBytes)) != -1) {
                // 拼接 unParsedByte 和新读取的数据
                byte[] buf;
                if (unParsedByte.length > 0) {
                    buf = new byte[unParsedByte.length + readLen];
                    System.arraycopy(unParsedByte, 0, buf, 0, unParsedByte.length);
                    System.arraycopy(readBytes, 0, buf, unParsedByte.length, readLen);
                    unParsedByte = new byte[0];
                } else if (readLen == readBytes.length) {
                    // 读满 blockSize 时直接引用，避免 256KB 拷贝
                    buf = readBytes;
                } else {
                    // 最后一次读取可能不满 blockSize
                    buf = Arrays.copyOf(readBytes, readLen);
                }

                int offset = 0;
                int total = buf.length;

                // 如果有残留的 header，先处理
                if (header != null) {
                    int remaining = total - offset;
                    if (header.getContentLength() > remaining) {
                        unParsedByte = Arrays.copyOfRange(buf, offset, total);
                        continue;
                    }
                    // 零拷贝：直接从 buf 读取密文，避免 cipherText 中间数组
                    cipherHandler.setIv(header.getIv());
                    cipherHandler.processDecryptByte(buf, offset, header.getContentLength(), outputStream, serializedContext);
                    offset += header.getContentLength();
                    header = null;
                }

                // 循环处理所有完整块（零拷贝优化）
                while (offset + fileHeaderLength <= total) {
                    // 零拷贝：直接从 buf 读取 header，避免 headerBytes 中间数组
                    tempHeader.deserializeFileFields(buf, offset, algorithm);
                    int contentLength = tempHeader.getContentLength();
                    offset += fileHeaderLength;

                    if (contentLength > total - offset) {
                        // 数据不完整，保存 header 和剩余数据
                        header = tempHeader;
                        unParsedByte = Arrays.copyOfRange(buf, offset, total);
                        offset = total;
                        break;
                    }

                    // 零拷贝：直接从 buf 读取密文，避免 cipherText 中间数组
                    cipherHandler.setIv(tempHeader.getIv());
                    cipherHandler.processDecryptByte(buf, offset, contentLength, outputStream, serializedContext);
                    offset += contentLength;
                }

                // 保存未处理的剩余数据
                if (offset < total) {
                    unParsedByte = Arrays.copyOfRange(buf, offset, total);
                }
            }

            // 处理文件末尾剩余数据
            while (unParsedByte != null && unParsedByte.length > 0) {
                if (header == null) {
                    if (unParsedByte.length < fileHeaderLength) {
                        break;
                    }
                    CipherHeader tailHeader = new CipherHeader();
                    byte[] headerBytes = Arrays.copyOfRange(unParsedByte, 0, fileHeaderLength);
                    tailHeader.deserializeFileFields(headerBytes, algorithm);
                    header = tailHeader;
                    unParsedByte = Arrays.copyOfRange(unParsedByte, fileHeaderLength, unParsedByte.length);
                }
                if (header.getContentLength() > unParsedByte.length) {
                    break;
                }
                byte[] cipherText = Arrays.copyOfRange(unParsedByte, 0, header.getContentLength());
                cipherHandler.setIv(header.getIv());
                cipherHandler.processDecryptByte(cipherText, cipherText.length, outputStream, serializedContext);
                unParsedByte = Arrays.copyOfRange(unParsedByte, header.getContentLength(), unParsedByte.length);
                header = null;
            }
        } catch (HuaweicloudException e) {
            throw e;
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.FILE_CHANGED_ERROR.getMessage());
        }

    }

}
