package com.huaweicloud.encryptionsdk.log;

import java.util.concurrent.atomic.AtomicLong;

public class LogMetrics {

    private final AtomicLong lastReportTime = new AtomicLong(0);
    private final AtomicLong successCount = new AtomicLong(0);
    private final AtomicLong failureCount = new AtomicLong(0);
    private final AtomicLong successLogCount = new AtomicLong(0);
    private final AtomicLong failureLogCount = new AtomicLong(0);
    private final AtomicLong bufferLogCount = new AtomicLong(0);
    private volatile String lastErrorMessage;
    private final AtomicLong lastErrorTime = new AtomicLong(0);

    public long getLastReportTime() {
        return lastReportTime.get();
    }

    public void setLastReportTime(long value) {
        lastReportTime.set(value);
    }

    public long getSuccessCount() {
        return successCount.get();
    }

    public void setSuccessCount(long value) {
        successCount.set(value);
    }

    public long getFailureCount() {
        return failureCount.get();
    }

    public void setFailureCount(long value) {
        failureCount.set(value);
    }

    public long getSuccessLogCount() {
        return successLogCount.get();
    }

    public void setSuccessLogCount(long value) {
        successLogCount.set(value);
    }

    public long getFailureLogCount() {
        return failureLogCount.get();
    }

    public void setFailureLogCount(long value) {
        failureLogCount.set(value);
    }

    public long getBufferLogCount() {
        return bufferLogCount.get();
    }

    public void setBufferLogCount(long value) {
        bufferLogCount.set(value);
    }

    public String getLastErrorMessage() {
        return lastErrorMessage;
    }

    public void setLastErrorMessage(String value) {
        lastErrorMessage = value;
    }

    public long getLastErrorTime() {
        return lastErrorTime.get();
    }

    public void setLastErrorTime(long value) {
        lastErrorTime.set(value);
    }

    public long incrementSuccessCount() {
        return successCount.incrementAndGet();
    }

    public long incrementFailureCount() {
        return failureCount.incrementAndGet();
    }

    public long addSuccessLogCount(long delta) {
        return successLogCount.addAndGet(delta);
    }

    public long addFailureLogCount(long delta) {
        return failureLogCount.addAndGet(delta);
    }

    public long addBufferLogCount(long delta) {
        return bufferLogCount.addAndGet(delta);
    }

    public static LogMetricsBuilder builder() {
        return new LogMetricsBuilder();
    }

    public void reset() {
        lastReportTime.set(0);
        successCount.set(0);
        failureCount.set(0);
        successLogCount.set(0);
        failureLogCount.set(0);
        bufferLogCount.set(0);
        lastErrorMessage = null;
        lastErrorTime.set(0);
    }

    public static class LogMetricsBuilder {
        private long lastReportTime;
        private long successCount;
        private long failureCount;
        private long successLogCount;
        private long failureLogCount;
        private long bufferLogCount;
        private String lastErrorMessage;
        private long lastErrorTime;

        public LogMetricsBuilder lastReportTime(long value) {
            this.lastReportTime = value;
            return this;
        }

        public LogMetricsBuilder successCount(long value) {
            if (value < 0) {
                throw new IllegalArgumentException("successCount must not be negative");
            }
            this.successCount = value;
            return this;
        }

        public LogMetricsBuilder failureCount(long value) {
            if (value < 0) {
                throw new IllegalArgumentException("failureCount must not be negative");
            }
            this.failureCount = value;
            return this;
        }

        public LogMetricsBuilder successLogCount(long value) {
            if (value < 0) {
                throw new IllegalArgumentException("successLogCount must not be negative");
            }
            this.successLogCount = value;
            return this;
        }

        public LogMetricsBuilder failureLogCount(long value) {
            if (value < 0) {
                throw new IllegalArgumentException("failureLogCount must not be negative");
            }
            this.failureLogCount = value;
            return this;
        }

        public LogMetricsBuilder bufferLogCount(long value) {
            if (value < 0) {
                throw new IllegalArgumentException("bufferLogCount must not be negative");
            }
            this.bufferLogCount = value;
            return this;
        }

        public LogMetricsBuilder lastErrorMessage(String value) {
            this.lastErrorMessage = value;
            return this;
        }

        public LogMetricsBuilder lastErrorTime(long value) {
            this.lastErrorTime = value;
            return this;
        }

        public LogMetrics build() {
            LogMetrics m = new LogMetrics();
            m.setLastReportTime(lastReportTime);
            m.setSuccessCount(successCount);
            m.setFailureCount(failureCount);
            m.setSuccessLogCount(successLogCount);
            m.setFailureLogCount(failureLogCount);
            m.setBufferLogCount(bufferLogCount);
            m.setLastErrorMessage(lastErrorMessage);
            m.setLastErrorTime(lastErrorTime);
            return m;
        }
    }
}
