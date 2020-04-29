# 0xFE_编程规范

- 使用UTF-8编码
- 使用空格缩进

## 命名

- 清晰表达意图, 少用缩写(行业通用除外, 如: request=req, response=resp, message=msg), 不应使用特殊前缀或后缀
- 用复数形式代表集合
- `\w{2,64}`, 除循环变量i, j, k, 异常e外

类型 | 命名风格
--- | ---
包 | 全小写, 点号分割, 允许数字, 无下划线
类, 接口, 枚举, 注解 | 名词/形容词, 大驼峰, 缩写也用大驼峰, 测试类加Test后缀
字段, 局部变量, 方法, 方法参数 | 介词/动词, 小驼峰, 测试方法可有下划线_
静态常量, 枚举 | 全大写, 下划线分割, 常见的Logger, Lock可除外
泛型 | 单个大写字母, 可接一个数字
异常 | 加后缀Exception
数据库 | 全小写下划线
表名 | 全大写下划线
列名 | 全大写下划线

## 变量

- 一个局部变量只表达一种含义, 避免前后不一致

## 安全编程

### 数据校验

#### 在信任边界以内(如Web服务端)进行数据校验

- 输入校验
- 输出校验

- 接收白名单: `Pattern.matches("^[0-9a-zA-Z_]+$", "abc_@123")`
- 拒绝黑名单, 白名单净化(对所有非字母数字删除/编码/替换), 黑名单净化(对某些特殊字符删除/编码/替换)

- 禁止使用assert校验

#### 防止命令注入

- `Runtime.exec()`
- `java.lang.ProcessBuilder`

#### 防止SQL注入

1. 参数化查询PreparedStatement, {==参数下标从1开始==}: `stmt.setString(1, userName);`
1. 存储过程`conn.prepareCall()`也不能拼接SQL再执行
1. Hibernate 原生SQL`session.createSQLQuery()`应使用参数化查询, HQL`session.createQuery()`应使用基于位置/名称的参数化查询
1. iBatis禁止使用`$`拼接SQL
1. 白名单校验(表名/字段名)
1. 转码

#### 文件路径校验前必须先进行标准化

- 等价路径: 软链接
- 目录遍历: 路径跨越`../`

- 必须使用getCanonicalPath(), 其他方法getPath(), getParent(), getAbsolutePath()均不会归一化

#### 解压

- 目录遍历
- DoS

- 错误示例

    ```java
    public class IODemo {
        private static final Logger log = Logger.getLogger(IODemo.class.getName());

        public static void zipIO(String path) {
            FileInputStream fin = null;
            BufferedInputStream bin = null;
            ZipInputStream zin = null;
            FileOutputStream fout = null;
            BufferedOutputStream bout = null;
            try {
                File zipFile = new File(path);
                // 解压到当前目录
                String parent = zipFile.getParent() + File.separator;
                fin = new FileInputStream(zipFile);
                bin = new BufferedInputStream(fin);
                zin = new ZipInputStream(bin);
                ZipEntry entry = null;
                int count;
                final int BUFFER_SIZE = 512;
                byte data[] = new byte[BUFFER_SIZE];
                // 对压缩包中的每个文件
                while ((entry = zin.getNextEntry()) != null) {
                    // toString()调用了getName()
                    log.info("Extracting: " + entry);

                    File unzipFile = new File(parent + entry.getName());
                    if (unzipFile.isDirectory()) {
                        // 目录
                        unzipFile.mkdir();
                    } else {
                        final int FILE_MAXSIZE = 0x6400000;  // 100MB
                        // 判断文件大小, 可以被伪造
                        if (entry.getSize() == -1 || entry.getSize() > FILE_MAXSIZE) {
                            throw new IllegalArgumentException("File is too big.");
                        }

                        fout = new FileOutputStream(unzipFile);
                        bout = new BufferedOutputStream(fout, BUFFER_SIZE);
                        while ((count = zin.read(data, 0, BUFFER_SIZE)) != -1) {
                            bout.write(data, 0, count);
                            bout.flush();
                        }
                    }

                    zin.closeEntry();
                }
            } catch (IOException e) {
                log.severe(e.getMessage());
            } finally {
                try {
                    bout.close();
                    fout.close();

                    zin.close();
                    bin.close();
                    fin.close();
                } catch (IOException e) {
                    log.severe(e.getMessage());
                }
            }
        }

        public static void main(String[] args) {
            zipIO("D:\\tmp\\io.zip");
        }
    }
    ```

- 推荐示例

    ```java
    public class IODemo {
        private static final Logger log = Logger.getLogger(IODemo.class.getName());

        public static void zipIO(String zipFilepath) {
            FileInputStream fin = null;
            BufferedInputStream bin = null;
            ZipInputStream zin = null;
            FileOutputStream fout = null;
            BufferedOutputStream bout = null;
            try {
                File zipFile = new File(zipFilepath);
                // 解压到当前目录
                String parent = zipFile.getParent() + File.separator;
                fin = new FileInputStream(zipFile);
                bin = new BufferedInputStream(fin);
                zin = new ZipInputStream(bin);
                ZipEntry entry = null;
                int count;
                final int BUFFER_SIZE = 512;
                byte data[] = new byte[BUFFER_SIZE];
                // 总解压文件数量
                final int TOTAL_FILE_NUM = 1000;
                // 总解压文件大小, 100MB
                final int TOTAL_FILE_MAXSIZE = 0x6400000;
                int totalFileNum = 0;
                int totalFileSize = 0;
                while ((entry = zin.getNextEntry()) != null) {
                    // 安全编程1: 校验解压文件数量
                    if (totalFileNum > TOTAL_FILE_NUM) {
                        throw new IllegalArgumentException("Too many files.");
                    }

                    // toString()调用了getName()
                    log.info("Extracting: " + entry);

                    File unzipFile = new File(parent + entry.getName());
                    // 安全编程2: 校验解压文件路径
                    String unzipFilepath = unzipFile.getCanonicalPath();
                    if (!unzipFilepath.startsWith(parent)) {
                        throw new IllegalArgumentException(
                                "File is outside extraction target directory");
                    }

                    if (unzipFile.isDirectory()) {
                        // 目录
                        unzipFile.mkdirs();
                    } else {
                        File dir = new File(unzipFile.getParent());
                        if (!dir.exists()) {
                            dir.mkdirs();
                        }

                        fout = new FileOutputStream(unzipFile);
                        bout = new BufferedOutputStream(fout, BUFFER_SIZE);
                        while ((count = zin.read(data, 0, BUFFER_SIZE)) != -1) {
                            // 安全编程3: 校验解压文件总大小
                            if (totalFileSize > TOTAL_FILE_MAXSIZE) {
                                throw new IllegalArgumentException("File is too big.");
                            }

                            bout.write(data, 0, count);
                            bout.flush();

                            totalFileSize += count;
                        }
                    }

                    zin.closeEntry();

                    totalFileNum++;
                }
            } catch (IOException e) {
                log.severe(e.getMessage());
            } finally {
                try {
                    if (bout != null) {
                        bout.close();
                    }
                    if (fout != null) {
                        fout.close();
                    }
                    if (zin != null) {
                        zin.close();
                    }
                    if (bin != null) {
                        bin.close();
                    }
                    if (fin != null) {
                        fin.close();
                    }
                } catch (IOException e) {
                    log.severe(e.getMessage());
                }
            }
        }

        public static void main(String[] args) {
            zipIO("D:\\tmp\\io.zip");
        }
    }
    ```

#### 防止CRLF和敏感信息记录日志

- 接收白名单
- 黑名单净化: `message = message.replace('\n', '_').replace('\r', '_');`

#### 防止拼接格式化字符串造成敏感信息泄露

```java
// 敏感信息: 信用卡失效时间
Calendar expirationDate = Calendar.getInstance();
expirationDate.set(2020, Calendar.FEBRUARY, 20);
// 客户端输入
// String input = "12";
// poc
String input = "Date: %1$tY-%1$tm-%1$te";

if (!String.valueOf(expirationDate.get(Calendar.DAY_OF_MONTH)).equals(input)) {
    // 存在格式化字符串注入
    System.out.printf(input + " did not match! HINT: It was issued in month "
            + "%1$tm.\n", expirationDate);
    // 正确使用
    System.out.printf("%s did not match! HINT: It was issued in month "
            + "%2$tm.\n", input, expirationDate);
}
```

#### 防止异常泄露敏感信息

- 敏感的异常消息
- 敏感的异常类型
    - FileNotFoundException
        1. 捕获并抛出IOException
        2. 自定义SecurityIOException继承IOException
        3. 不抛出异常, 只打印简单日志
        4. 白名单

异常名称 | 信息泄露或威胁描述
--- | ---
java.io.FileNotFoundException | 泄露文件系统结构和文件名列举
java.util.jar.JarException | 泄露文件系统结构
java.util.MissingResourceException | 资源列举
java.security.acl.NotOwnerException | 所有人列举
java.util.ConcurrentModificationException | 可能提供线程不安全的代码信息
javax.naming.InsufficientResourcesException | 服务器资源不足（可能有利于DoS攻击）
java.net.BindException | 当不信任客户端能够选择服务器端口时造成开放端口列举
java.lang.OutOfMemoryError | DoS
java.lang.StackOverflowError | DoS
java.sql.SQLException | 数据库结构，用户名列举
JSONException | -

#### 防止空指针

- 调用null的方法, 如`obj=null; obj.equals(xxx);`, `String s=null; s.split(" ");`
- 访问null的属性
- 获取null数组的长度
- 访问数组中的null元素

#### 防止除0

- 除法: `/`
- 模: `%`

### 多线程

#### 防止锁暴露

- 同步方法
- 同步this的代码块
- 同步public static锁的代码块

正确示例:

```java
public class LockDemo {
    private final Object LOCK = new Object();

    public void changeValue() {
        synchronized (LOCK) {
            // ...
        }
    }
}
```

#### 锁类型

错误示例:

- Boolean只有两个值
- 基础数据类型的包装类自动装箱

    ```java
    private int count = 0;
    private final Integer LOCK = count;
    ```

- 字符串常量: `private final String LOCK = "LOCK";`
- Interned String对象: `private final String LOCK = new String("LOCK").intern();`, 在常量池中
- getClass(): 子类和基类, 类和内部类获取到的对象不同
- 内置锁

    ```java
    private final Lock LOCK = new ReentrantLock();

    public void changeValue() {
        synchronized (LOCK) {
            // ...
        }
    }
    ```

正确示例:

- 基础数据类型的包装类

    ```java
    private int count = 0;
    private final Integer LOCK = new Integer(count);
    ```

- 字符串实例: `private final String LOCK = new String("LOCK");`
- Object
- Base.class/Class.forName("Base"): 明确类名

#### 保护静态数据

错误示例:

```java
// 静态数据
private static volatile int counter;
// 非静态锁对象
private final Object LOCK = new Object();
```

```java
private static volatile int counter;

public synchronized void run() {
    // ...
}
```

正确示例:

```java
private static volatile int counter;

private static final Object LOCK = new Object();
```

#### 保证顺序获得和释放多个锁

#### 在finally中释放锁

#### 禁止调用Thread.run()在当前线程中执行run()

#### 禁止调用Thread.stop()导致线程非正常释放锁

1. 通过修改volatile变量终止线程中的循环
2. 调用Thread.interrupt()终止线程中的循环

#### 禁止非线程安全的方法覆写线程安全的方法

### IO

#### 使用File.createTempFile创建临时文件, finally删除

#### 使用asReadOnlyBuffer()返回Buffer的只读视图

#### 防止阻塞在外部进程

```java
Runtime rt = Runtime.getRuntime();
Process proc = rt.exec("notepad.exe");
// java.lang.IllegalThreadStateException: process has not exited
int exitVal = proc.exitValue();
```

```java
Runtime rt = Runtime.getRuntime();
Process proc = rt.exec("notepad.exe");
// 一直阻塞到外部进程终止
int exitVal = proc.waitFor();
```

#### 使用int保存read()的返回值

### 序列化

#### 使用transient保护敏感信息

#### 序列化敏感数据时先签名后加密, 防止签名被篡改后正常数据校验不通过

#### 禁止序列化非静态的内部类

#### 如果某敏感操作使用安全管理器检查, 防止反序列化绕过

#### 防止反序列化注入

- 二进制
- xml
    - XMLDecoder, 无消减措施
    - XStream, setupDefaultSecurity()或addPermission白名单

- json: fastjson, jackson
    - type白名单
