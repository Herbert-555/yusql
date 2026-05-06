package com.yusql.engine;

import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class TaskQueue {
    private final BlockingQueue<ScanTask> queue;
    private final AtomicInteger maxSize;

    public TaskQueue(int maxSize) {
        this.maxSize = new AtomicInteger(maxSize);
        this.queue = new LinkedBlockingQueue<>(maxSize);
    }

    public boolean offer(ScanTask task) {
        if (queue.size() >= maxSize.get()) return false;
        return queue.offer(task);
    }

    public ScanTask poll() throws InterruptedException {
        return queue.poll(500, TimeUnit.MILLISECONDS);
    }

    public int size() { return queue.size(); }
    public boolean isEmpty() { return queue.isEmpty(); }
    public void clear() { queue.clear(); }
    public void setMax(int max) {
        if (max > 0) maxSize.set(max);
    }
    public int getMax() { return maxSize.get(); }
}
