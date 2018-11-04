---
title: Java排序
date: 2018-11-04 22:03:23
categories: java
tags:
---

# PriorityQueue

带优先级的队列，使用poll方法按序获取元素。
队列元素需实现Comparable接口的compareTo方法。
非线程安全。

```java
import java.util.Arrays;
import java.util.Objects;

public class Record implements Comparable {

    private String orderKey;

    private byte[] originalData;

    public Record(String orderKey, byte[] originalData)
    {
        this.orderKey = orderKey;
        this.originalData = originalData;
    }

    public String getOrderKey() {
        return orderKey;
    }

    public void setOrderKey(String orderKey) {
        this.orderKey = orderKey;
    }

    public byte[] getOriginalData() {
        return originalData;
    }

    public void setOriginalData(byte[] originalData) {
        this.originalData = originalData;
    }

    @Override
    public int compareTo(Object o) {
        //按照从小到大排序
        Record record = (Record) o;
        if(this.orderKey.compareTo(record.getOrderKey()) < 0)
        {
            return -1;
        }
        else if(this.orderKey.compareTo(record.getOrderKey()) > 0)
        {
            return 1;
        }
        return 0;
    }

    /**
     * 实现equals方法，方便PriorityQueue中的contains方法判断
     * @param o object
     * @return true false
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Record record = (Record) o;
        return orderKey.equals(record.orderKey);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(orderKey);
        result = 31 * result + Arrays.hashCode(originalData);
        return result;
    }

    @Override
    public String toString() {
        return "Record{" +
                "orderKey='" + orderKey + '\'' +
                ", originalData=" + Arrays.toString(originalData) +
                '}';
    }
}


import java.util.PriorityQueue;

public class PriorityQueueDemo {

    private static final PriorityQueue<Record> priorityQueue = new PriorityQueue<>();

    private final Object LOCK = new Object();

    public void addRecord(Record record)
    {
        synchronized (LOCK)  //PriorityQueue的add方法不是线程安全的，需要加锁控制
        {
            if(!priorityQueue.contains(record))
            {
                System.out.println(Thread.currentThread() + ": " + record.getOrderKey());
                priorityQueue.add(record);
            }
        }
    }

    public static void main(String args[]) throws InterruptedException {
        PriorityQueueDemo priorityQueueDemo = new PriorityQueueDemo();

        Thread t1 = new Thread(){
            public void run()
            {
                System.out.println("t1 started..");
                priorityQueueDemo.addRecord(new Record("abc", new byte[]{'e','b'}));
                priorityQueueDemo.addRecord(new Record("efg", new byte[]{'e','b'}));
                priorityQueueDemo.addRecord(new Record("def", new byte[]{'e','b'}));
                priorityQueueDemo.addRecord(new Record("bcd", new byte[]{'e','b'}));
                priorityQueueDemo.addRecord(new Record("cde", new byte[]{'e','b'}));
            }
        };

        Thread t2 = new Thread(){
            public void run()
            {
                System.out.println("t2 started..");
                priorityQueueDemo.addRecord(new Record("abc", new byte[]{'e','b'}));
                priorityQueueDemo.addRecord(new Record("efg", new byte[]{'e','b'}));
                priorityQueueDemo.addRecord(new Record("def", new byte[]{'e','b'}));
                priorityQueueDemo.addRecord(new Record("bcd", new byte[]{'e','b'}));
                priorityQueueDemo.addRecord(new Record("cde", new byte[]{'e','b'}));
            }
        };

        Thread t3 = new Thread(){
            public void run()
            {
                System.out.println("t3 started..");
                priorityQueueDemo.addRecord(new Record("abc", new byte[]{'e','b'}));
                priorityQueueDemo.addRecord(new Record("efg", new byte[]{'e','b'}));
                priorityQueueDemo.addRecord(new Record("def", new byte[]{'e','b'}));
                priorityQueueDemo.addRecord(new Record("bcd", new byte[]{'e','b'}));
                priorityQueueDemo.addRecord(new Record("cde", new byte[]{'e','b'}));
            }
        };

        t1.start();
        t2.start();
        t3.start();
        t1.join();  //等待调用join的线程执行完毕。t1.join(10);表示等待10毫秒。
        t2.join();
        t3.join();

        System.out.println("------ 运行结果 ---------");
        while(!priorityQueue.isEmpty())
        {
            System.out.println(priorityQueue.poll());
        }
    }
}
```
