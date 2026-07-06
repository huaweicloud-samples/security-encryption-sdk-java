package com.huaweicloud.encryptionsdk.model;

public class CryptoResult<T> {

    private T result;

    private CipherHeader headers;

    private long dataLength;

    public CryptoResult(T result, CipherHeader headers) {
        this.result = result;
        this.headers = headers;
    }

    public CryptoResult(T result, CipherHeader headers, long dataLength) {
        this(result, headers);
        this.dataLength = dataLength;
    }

    public T getResult() {
        return result;
    }

    public void setResult(T result) {
        this.result = result;
    }

    public CipherHeader getHeaders() {
        return headers;
    }

    public void setHeaders(CipherHeader headers) {
        this.headers = headers;
    }

    public long getDataLength() {
        return dataLength;
    }
}
