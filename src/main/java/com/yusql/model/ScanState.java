package com.yusql.model;

import java.util.concurrent.atomic.AtomicInteger;

public class ScanState {
    private volatile boolean running;
    private final AtomicInteger scanned = new AtomicInteger(0);
    private final AtomicInteger skipped = new AtomicInteger(0);
    private final AtomicInteger totalSent = new AtomicInteger(0);
    private final AtomicInteger successSent = new AtomicInteger(0);

    public boolean isRunning() { return running; }
    public void setRunning(boolean v) { running = v; }
    public int getScanned() { return scanned.get(); }
    public void incScanned() { scanned.incrementAndGet(); }
    public int getSkipped() { return skipped.get(); }
    public void incSkipped() { skipped.incrementAndGet(); }
    public int getTotalSent() { return totalSent.get(); }
    public int getSuccessSent() { return successSent.get(); }
    public void addSent(boolean success) { totalSent.incrementAndGet(); if (success) successSent.incrementAndGet(); }
    public void reset() { scanned.set(0); skipped.set(0); totalSent.set(0); successSent.set(0); }
}
