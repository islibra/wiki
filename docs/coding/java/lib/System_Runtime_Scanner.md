# System_Runtime_Scanner

## Object

```java
package java.lang;

// 是否同一个对象
public boolean equals(Object obj)
// 根据对象地址计算HashCode System.identityHashCode(Object x)
public native int hashCode()
// 运行时类名@十六进制HashCode
public String toString()
// 通过对象获取类
public final native Class<?> getClass()
// GC调用
protected void finalize()
// 自定义类实现Cloneable空接口并重写clone()
protected native Object clone()


// 输出null的hashCode为0
log.info("Objects.hashCode: " + Objects.hashCode(null));
// 输出null
log.info("Objects.toString: " + Objects.toString(null));
// 检查如果为null, 抛出java.lang.NullPointerException
Objects.requireNonNull(null);
```


## System

```java
package java.lang;


// 系统环境变量
Map<String, String> env = System.getenv();
for (String name : env.keySet()) {
    log.info(name + ": " + System.getenv(name));
}

// 系统属性
Properties props = System.getProperties();
log.info("System.getProperties: " + props.get("os.name"));
try {
    props.store(new FileOutputStream("D:\\tmp\\props.txt"), "System Properties");
} catch (IOException e) {
    log.severe(e.getMessage());
}

// 毫秒
log.info("System.currentTimeMillis: " + System.currentTimeMillis());
// 纳秒
log.info("System.nanoTime: " + System.nanoTime());

// 重定向标准输入输出流
System.setIn(fis)
System.setOut(fos)
```


## Runtime

```java
Runtime run = Runtime.getRuntime();
log.info("availableProcessors: " + run.availableProcessors());
log.info("totalMemory: " + run.totalMemory());
log.info("freeMemory: " + run.freeMemory());
log.info("maxMemory: " + run.maxMemory());
try {
    run.exec("notepad.exe");
} catch (IOException e) {
    log.severe(e.getMessage());
}
```


## Scanner

```java
import java.util.Scanner;

// 使用Scanner获取键盘输入
Scanner scan = new Scanner(System.in);
// 读取文件输入
// Scanner scan = new Scanner(new File("xxx.txt"));
// 设置分隔符, 默认空格, TAB, 换行
scan.useDelimiter("\\n");
// hasNextLine/hasNextLong
while (scan.hasNext()) {
    // nextLine/nextLong
    log.info(scan.next());
}
```
