# Logger

```java
import java.util.logging.Level;
import java.util.logging.Logger;

// 设置日志级别, 对后续代码生效
Logger.getGlobal().setLevel(Level.OFF);

// 使用全局日志记录器打印日志
// 四月 09, 2020 9:09:57 下午 libdemo.ExceptionDemo main
// 信息: xxx
Logger.getGlobal().info("xxx");

// 自定义日志记录器
private static final Logger log = Logger.getLogger(Demo.class.getName());
log.info("xxx");
log.log(Level.INFO, "xxx");

// 记录详细调用栈, 默认FINER级别
// 修改配置中的日志级别C:\Java\jdk1.8.0_241\jre\lib\logging.properties
// java.util.logging.ConsoleHandler.level = ALL
log.setLevel(Level.ALL);
log.entering("package.Demo", "method", args);
log.logp(Level.INFO, "package.Demo", "method", "detail");
log.exiting("package.Demo", "method", args);

// 记录异常
log.log(Level.WARNING, "wrong number format", e);
log.throwing("package.Demo", "method", e);

// 安装自定义处理器
log.setLevel(Level.ALL);
log.setUseParentHandlers(false);
Handler handler = new ConsoleHandler();
handler.setLevel(Level.ALL);
log.addHandler(handler);
// 文件处理器, 默认路径C:\Users\xxx\java0.log, 默认Level.ALL
// Handler fileHandler = new FileHandler();
final int NOLIMIT = 0;
final int CIRCLE = 1;
final boolean ISAPPEND = true;
Handler fileHandler = new FileHandler("D:\\tmp\\app.log", NOLIMIT, CIRCLE, ISAPPEND);
handler.setLevel(Level.ALL);
log.addHandler(fileHandler);
```

## 日志级别

1. OFF: 关闭, turn off
1. SEVERE: 严重, serious failure
1. WARNING: 告警, potential problem
1. INFO(默认): 提示, informational messages
1. CONFIG: 配置, configuration messages
1. FINE: tracing information
1. FINER: detailed tracing message
1. FINEST: highly detailed tracing message
1. ALL: all messages

## 指定配置文件路径

```bash
$ java -Djava.util.logging.config.file=configFile MainClass
```

## 文件处理器配置参数

- java.util.logging.FileHandler.level = Level.ALL
- java.util.logging.FileHandler.pattern = %h/java%u.log
- java.util.logging.FileHandler.append = false, 是否在已存在的文件尾部追加写入
- java.util.logging.FileHandler.limit = 50000, 最大字节数, 0表示无限制
- java.util.logging.FileHandler.count = 1, 循环日志数量
- java.util.logging.FileHandler.formatter = java.util.logging.XMLFormatter

### 文件模式

- %h: 用户主目录
- %t: 系统临时目录
- %u: 为解决冲突的唯一编号, 如app0.log
- %g: 循环计数, 如app.log.0
- %%: %字符
