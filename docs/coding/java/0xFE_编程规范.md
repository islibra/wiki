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

1. 在信任边界以内(如Web服务端)进行数据校验
    - 输入校验
    - 输出校验

    - 接收白名单: `Pattern.matches("^[0-9a-zA-Z_]+$", "abc_@123")`
    - 拒绝黑名单, 白名单净化(对所有非字母数字删除/编码/替换), 黑名单净化(对某些特殊字符删除/编码/替换)

    - 禁止使用assert校验

1. 防止命令注入
    - `Runtime.exec()`
    - `java.lang.ProcessBuilder`

1. 防止SQL注入
    1. 参数化查询PreparedStatement, {==参数下标从1开始==}: `stmt.setString(1, userName);`
    1. 存储过程`conn.prepareCall()`也不能拼接SQL再执行
    1. Hibernate 原生SQL`session.createSQLQuery()`应使用参数化查询, HQL`session.createQuery()`应使用基于位置/名称的参数化查询
    1. iBatis禁止使用`$`拼接SQL
    1. 白名单校验(表名/字段名)
    1. 转码

1. 文件路径校验前必须先进行标准化
    - 等价路径: 软链接
    - 目录遍历: 路径跨越`../`

    - 必须使用getCanonicalPath(), 其他方法getPath(), getParent(), getAbsolutePath()均不会归一化

1. 解压
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

1. 防止CRLF和敏感信息记录日志
    - 接收白名单
    - 黑名单净化: `message = message.replace('\n', '_').replace('\r', '_');`

1. 防止拼接格式化字符串造成敏感信息泄露

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
