# 0x02_深入理解JVM

Java与C/C++最大的区别：内存动态分配和垃圾收集，无需为new写delete/free。

## 内存模型

### 一、方法区

所有 {==线程共享==} 的内存区域。

存储已被JVM加载的 **class**, jar, **常量**, **静态变量**, 即时编译器编译后的代码等, 包含类名称, 类型(枚举, 类, 接口), 字段, 方法

> HotSpot虚拟机的设计团队把GC扩展至方法区，并成为永久代（**Permanent Generation**）, 使用参数-XX:MaxPermSize设置上限, 更容易出现内存溢出。JDK8已搬迁至本地内存(Native Memory)中的元空间(Meta-space)。

垃圾回收较少，主要针对 **常量池和对类型的卸载** 。

#### 异常

- OutOfMemoryError，方法区无法满足内存分配需求。

#### 运行时常量池

用于存放编译期生成的字面量和符号引用，在类加载后存放到方法区的运行时常量池中。

### 二、堆

Java应用 1:1 JVM实例 1:1 堆

所有{==线程共享==}的一块内存区域，在虚拟机启动时创建。

存储 **new** 对象实例, this指针, **数组**

{==GC的主要区域==}

在启动参数中通过 **-Xms初始值** 和 **-Xmx最大值** 控制。

#### 异常

- OutOfMemoryError: 堆中没有内存完成实例分配，并且堆无法再扩展。

#### GC

新生代(Eden8:From Survivor1:To Survivor1):老年代4

##### 新生代

频繁触发MinorGC

- Eden
- From Survivor: 上一次GC幸存者
- To Survivor: 上一次MinorGC幸存者

复制：

1. eden,from复制到to，年龄+1
1. 清空eden, from
1. to->from

##### 老年代

年龄15->老年代

MajorGC

标记清除：扫描全量，回收没有标记的对象，产生碎片。

大对象直接放入老年代，不足时OOM。

### 三、Java虚拟机栈

生命周期与线程相同

{==线程私有==}

Java **方法** 执行时，创建一个Stack Frame(栈帧)，用于存储 **局部变量表** 、操作数栈、动态链接、方法出口 **(返回值)** 等信息。

#### 局部变量表

- 编译期可知的基本数据类型（boolean/byte/char/short/int/float/long/double）
- 对象引用（reference）: 可能是一个指向对象起始地址的引用指针，也可能是指向一个代表对象的句柄
- returnAddress类型（指向字节码指令的地址）。

局部变量表所需的 **内存空间在编译期间完成分配**，运行期间不会改变。

#### 异常

+ StackOverflowError，请求栈深度大于虚拟机允许的深度时。
+ OutOfMemoryError，如果Java虚拟机栈容量可以动态扩展({==HotSpot虚拟机的栈容量无法动态扩展==}), 无法申请到足够的内存时。

### 四、本地方法栈

与Java虚拟机栈相同，为虚拟机使用到的其他语言的Native方法服务。

> Hot-Spot虚拟机将本地方法栈和Java虚拟机栈合二为一

### 五、程序计数器

当前线程所执行的字节码的 **行号** 指示器，每条线程独立的 {==线程私有==} 内存空间。

- 如果线程正在执行的是一个Java方法，这个计数器记录的是正在执行的虚拟机字节码指令的地址；
- 如果正在执行的是本地（Native）方法，这个计数器值则应为空（Undefined）。

**无OutOfMemoryError。**

### 六、直接内存(Direct Memory)

NIO(New Input/Output)中引入Channel和Buffer，可以使用Native函数库直接分配 **堆外内存** ，然后通过一个存储在Java堆里面的DirectByteBuffer对象作为这块内存的引用进行操作。

不受Java堆大小限制，受本机总内存（RAM、SWAP区或分页文件）大小及处理器寻址空间限制。

#### 异常

- OutOfMemoryError, 动态扩展时超过物理内存限制


!!! quote "参考链接"
    - [JVM调优：基本概念](https://mp.weixin.qq.com/s/iqgoKZOWz_RXxqclwoQlHg)


## 类加载

Java虚拟机把描述类的数据, 从class文件加载到内存(方法区), 并对数据进行校验、转换解析和初始化，最终形成可被虚拟机直接使用的Java类型。

运行期间进行, 当Java程序第一次使用某个类中的内容，而该类的字节码文件在内存中不存在时，类加载器就会去加载该类的字节码文件。

!!! example "编写一个面向接口的应用, 运行时通过Java预置或 {==自定义的类加载器==}, 从网络加载一个 {==二进制字节流==}作为实际的实现类"

!!! note "JVM终止场景"
    1. 运行正常结束
    1. System.exit(), Runtine.getRuntime.exit()
    1. 遇到未捕获异常
    1. 强制结束JVM进程

### 1. 加载(Loading)

1. 通过类 **全限定名** 获取定义类的 **二进制字节流**
    - class文件
    - jar/war
    - Applet
    - 运行时计算生成, 如动态代理
    - JSP
    - 数据库
    - 加密class文件

1. 将字节流的静态存储结构转化为 **方法区** 的运行时数据结构
1. 在内存中生成一个代表这个类的 **java.lang.Class** 对象, 作为方法区这个类的各种数据的访问 **入口**

#### 类加载器

- 数组类不通过类加载器创建，而由JVM直接在内存中构建，但数组元素类由加载器加载。
- 在JVM中, 以全限定类名和其类加载器作为唯一标识

##### 层次结构

1. Bootstrap ClassLoader: 根类加载器，主要负责加载Java的核心类。除了根类加载器，其他类加载器都由Java实现。

    ```java
    import java.net.URL;

    public class BootstrapClassLoaderTest {
        public static void main(String[] args) {
            URL[] urls = sun.misc.Launcher.getBootstrapClassPath().getURLs();
            // 获取根类加载器所加载的核心类库
            // file:/C:/Java/jdk1.8.0_241/jre/lib/resources.jar
            // file:/C:/Java/jdk1.8.0_241/jre/lib/rt.jar
            // file:/C:/Java/jdk1.8.0_241/jre/lib/sunrsasign.jar
            // file:/C:/Java/jdk1.8.0_241/jre/lib/jsse.jar
            // file:/C:/Java/jdk1.8.0_241/jre/lib/jce.jar
            // file:/C:/Java/jdk1.8.0_241/jre/lib/charsets.jar
            // file:/C:/Java/jdk1.8.0_241/jre/lib/jfr.jar
            // file:/C:/Java/jdk1.8.0_241/jre/classes
            for (URL url : urls) {
                System.out.println(url.toExternalForm());
            }
        }
    }
    ```

    > 通过java.exe -Xbootclasspath或-Dsun.boot.class.path指定加载附加的类

2. Extension ClassLoader: 扩展类加载器, 主要负载加载`%JAVA_HOME%/jre/lib/ext/* .jar`或`java.ext.dirs`系统属性指定的目录，该类加载器在JDK1.9的时候更名为：Platform ClassLoader, 其父类加载器为: null。
3. System ClassLoader: 系统类加载器, 应用程序类加载器(ApplicationClassLoader)，主要负责加载由`-classpath`或`java.class.path`系统属性或`classpath`环境变量所指定的jar包和类。该类加载器在JDK1.9的时候更名为：System ClassLoader, 其父类加载器为：ExtensionClassLoader。

    > 通过ClassLoader.getSystemClassLoader()获取系统类加载器

    ```java
    import java.io.IOException;
    import java.net.URL;
    import java.util.Enumeration;

    public class SystemClassLoaderTest {
        public static void main(String[] args) throws IOException {
            // 获取系统类加载器
            ClassLoader systemLoader = ClassLoader.getSystemClassLoader();
            // sun.misc.Launcher$AppClassLoader@18b4aac2
            System.out.println(systemLoader);
            // 获取系统类加载器的加载路径
            // 默认是classpath环境变量或当前路径
            Enumeration<URL> em = systemLoader.getResources("");
            while (em.hasMoreElements()) {
                System.out.println(em.nextElement());
            }
            // 获取扩展类加载器
            ClassLoader extensionLoader = systemLoader.getParent();
            // sun.misc.Launcher$ExtClassLoader@1b6d3586
            System.out.println(extensionLoader);
            // 扩展类加载器的加载路径
            // C:\Java\jdk1.8.0_241\jre\lib\ext;C:\windows\Sun\Java\lib\ext
            System.out.println(System.getProperty("java.ext.dirs"));
            // 扩展类加载器的父类加载器
            // null
            System.out.println(extensionLoader.getParent());
        }
    }
    ```

4. 自定义类加载器(UserClassLoader)，负责加载程序员指定目录下的字节码文件。继承ClassLoader，重写findClass()（推荐）和loadClass()。
    - loadClass()执行步骤
        1. findLoadedClass(String), 缓存机制
        1. 调用父/根类加载器的loadClass(), 父类委托
        1. findClass()

    - final defineClass(String name, byte[] b, int off, int len), 将class文件读入字节数组b, 并将其转换为Class对象

    ```java
    import java.io.File;
    import java.io.FileInputStream;
    import java.io.FileNotFoundException;
    import java.io.IOException;
    import java.lang.reflect.Method;

    /**
     * 读取某个java文件并编译成class, 加载并调用其静态方法demoStaticMethod()
     */
    public class CustomClassLoader extends ClassLoader {
        /**
         * 编译指定源文件
         *
         * @param javaFilename 源文件名称
         * @return 编译是否成功
         */
        private boolean compile(String javaFilename) {
            try {
                Process p = Runtime.getRuntime().exec("javac " + javaFilename);
                p.waitFor();
                int ret = p.exitValue();
                return ret == 0;
            } catch (IOException | InterruptedException e) {
                System.out.println(e);
            }
            return false;
        }

        /**
         * 将指定文件内容读取进数组
         *
         * @param filename 文件名称
         * @return 数组
         * @throws IOException 读取失败
         */
        private byte[] getBytes(String filename) throws IOException {
            File file = new File(filename);
            long len = file.length();
            byte[] raw = new byte[(int) len];
            try {
                FileInputStream fin = new FileInputStream(file);
                int ret = fin.read(raw);
            } catch (FileNotFoundException e) {
                System.out.println(e);
            }
            return raw;
        }

        /**
         * 继承ClassLoader并重写findClass()
         *
         * @param name 类全限定名
         * @return 类
         */
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            Class clazz = null;
            String basePath = "/Users/lixiaolong/code/java/";
            // 将包路径中的.替换成/
            String fileStub = name.replace(".", "/");
            String javaFilename = basePath + fileStub + ".java";
            String classFilename = basePath + fileStub + ".class";
            System.out.println(javaFilename);
            File javaFile = new File(javaFilename);
            File classFile = new File(classFilename);
            // 源文件存在
            if (javaFile.exists()) {
                // 字节码文件不存在, 或源文件修改时间晚于字节码修改时间
                if (!classFile.exists() || javaFile.lastModified() > classFile.lastModified()) {
                    // 重新编译
                    if (!compile(javaFilename) || !classFile.exists()) {
                        throw new ClassNotFoundException();
                    }
                }
            }
            if (classFile.exists()) {
                try {
                    // 将class文件的二进制字节码读入数组
                    byte[] raw = getBytes(classFilename);
                    // 将二进制字节码转化为class
                    clazz = defineClass(name, raw, 0, raw.length);
                } catch (IOException e) {
                    System.out.println(e);
                }
            }
            if (clazz == null) {
                throw new ClassNotFoundException();
            }
            return clazz;
        }

        public static void main(String[] args) {
            // 全限定名
            String className = "HelloJava";
            // 参数列表
            String[] progArgs = {"a", "b", "c"};
            CustomClassLoader ccl = new CustomClassLoader();
            try {
                // 加载
                Class clazz = ccl.loadClass(className);
                // 获取类方法, 参数为字符串数组
                Method m = clazz.getMethod("demoStaticMethod", new String[0].getClass());
                // 反射调用, 注意这里的参数列表要转化成Object数组
                Object[] objArgs = {progArgs};
                m.invoke(null, objArgs);
            } catch (Exception e) {
                System.out.println(e);
            }
        }
    }


    public class HelloJava {
        public static void demoStaticMethod(String[] args) {
            for (String arg : args) {
                System.out.println(arg);
            }
        }   
    }
    ```

5. URLClassLoader

抽象类ClassLoader的实现类

```java
public class URLClassLoaderDemo {
    public static void main(String[] args) {
        try {
            // 从本地文件系统或远程主机获取二进制文件来加载类, file:, http:, ftp:
            URL[] urls = {new URL("file:mysql-connector-java-5.1.30-bin.jar")};
            // 使用默认的ClassLoader作为父类, 创建URLClassLoader
            URLClassLoader myClassLoader = new URLClassLoader(urls);
            Class clazz = myClassLoader.loadClass("com.mysql.jdbc.Driver");
            // 实例化
            Driver driver = (Driver) clazz.newInstance();
            // ...
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
```

!!! quote "参考链接: [Java中类加载器的工作原理 | 技术](https://mp.weixin.qq.com/s/0OUPf3WzQCsKLeZPjo6c9Q)"

##### 类加载机制

1. 全盘负责: 由同一个类加载器负责加载某个Class和其依赖/引用的其他Class
1. 父类委托: 先让父类加载器尝试加载Class
1. 缓存机制: **修改并替换class文件后, 必须重启JVM生效**


### 2. 连接(Linking)

#### a. 验证(Verification)

校验二进制字节流的类结构是否正确

#### b. 准备(Preparation)

为类变量分配内存，设置初始值

#### c. 解析(Resolution)

将符号引用替换为直接引用

### 3. 初始化(Initialization)

#### 初始化时机

1. 虚拟机启动时, 初始化包含 **main()** 的主类
1. 由new, getstatic, putstatic, invokestatic指令触发

    - 使用new关键字实例化对象
    - 读取或设置类静态字段

        > 被final修饰的常量, 已在编译期间把结果放入常量池

    - 调用类静态方法

1. 初始化类的时候, 如果其父类还没有初始化

    > 父接口除外

1. Class.forName()
1. 使用java.lang.reflect包的方法对类进行反射调用的时候
1. 反序列化
1. JDK 7: java.lang.invoke.MethodHandle实例解析结果为REF_getStatic, REF_putStatic, REF_invokeStatic, REF_newInvokeSpecial
1. JDK 8: 接口中定义了被default关键字修饰的方法, 接口的实现类初始化时

!!! note "被动引用, 不会触发类初始化"
    1. 通过子类, 引用父类的静态字段, 只会导致父类初始化, 不会导致子类初始化

        ```java
        public class SuperClass {
            static {
                System.out.println("SuperClass init");
            }

            public static int value = 123;
        }

        public class SubClass extends SuperClass {
            static {
                System.out.println("SubClass init");
            }
        }

        public class PassiveReference {
            public static void main(String[] args) {
                // SuperClass init
                // 123
                System.out.println(SubClass.value);
            }
        }
        ```

    1. 通过数组定义, 引用类, 不会触发类初始化

        ```java
        public class PassiveReference {
            public static void main(String[] args) {
                SuperClass[] spCls = new SuperClass[3];
            }
        }
        ```

        !!! tip "会触发[Lxxx.SuperClass的类初始化, 由虚拟机自动生成, 继承于java.lang.Object, 由newarray指令触发"
            代表一维数组, 包含length属性和clone()方法, 当数组越界时, 会抛出java.lang.ArrayIndexOutOfBoundsException

    1. 常量在 **编译阶段** 会存入 **调用类** 的常量池中, 本质上没有直接引用到定义常量的类, 因此不会触发定义常量的类初始化

        ```java
        public class ConstClass {
            static {
                System.out.println("ConstClass init");
            }

            public static final String HELLOWORLD = "hello world";
        }

        public class PassiveReference {
            public static void main(String[] args) {
                System.out.println(ConstClass.HELLOWORLD);
            }
        }
        ```

        但如果final修饰的值在编译时无法确定, 则会触发类初始化

        ```java
        public class ConstClass {
            static {
                System.out.println("ConstClass init");
            }

            public static final String NOW = System.currentTimeMillis() + "";
        }

        public class PassiveReference {
            public static void main(String[] args) {
                System.out.println(ConstClass.NOW);
            }
        }
        ```

    1. 使用ClassLoader.loadClass()只会加载类, 不会初始化, 使用Class.forName()才会初始化

        ```java
        public class PassiveReference {
            public static void main(String[] args) throws ClassNotFoundException {
                ClassLoader cl = ClassLoader.getSystemClassLoader();
                cl.loadClass("jvm.ConstClass");
                System.out.println("load class...");

                Class.forName("jvm.ConstClass");
            }
        }
        ```

#### 对类变量指定初始值

1. 声明变量时指定初始值: `static int a = 5;`
1. 使用静态初始化块为类变量指定初始值

    ```java
    static int b;
    static {
        b = 6;
    }
    ```

### 4. 使用(Using)

### 5. 卸载(Unloading)


## 安全管理器(默认不安装, 所有操作都被允许)

!!! abstract "用来保护敏感操作, 当系统 {==需要加载不可信的代码时==}, 必须 {==安装安全管理器==}, 且敏感操作必须经过安全管理器检查, 从而防止其被不可信代码调用"
    - 已使用安全管理器检查的敏感操作的API
        - 访问本地文件
        - 向外部主机开放套接字连接
        - 创建类加载器

    - 应用自定义敏感操作
        1. 自定义安全策略
        2. 操作前增加安全管理器检查
        3. 安装安全管理器

    - 如果类构造方法引入了安全管理器检查, 则其必须实现反序列化自动调用方法readObject并进行安全检查

```java
package java.lang;

public class Runtime {
    // 敏感操作
    public void exit(int status) {
        // 获取安全管理器 java.lang.SecurityManager
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            // 检查权限, 抛出异常 SecurityException
            security.checkExit(status);
        }

        // 检查通过, 执行操作
        Shutdown.exit(status);
    }
}


package java.lang;

public class SecurityManager {
    public void checkExit(int status) {
        checkPermission(new RuntimePermission("exitVM."+status));
    }

    public void checkPermission(Permission perm) {
        java.security.AccessController.checkPermission(perm);
    }
}
```

### 权限

permission className targetName, actionList;

- public abstract class java.security.Permission
    - AllPermission
    - public final class java.io.FilePermission: read, write, execute, delete
        - file
        - directory
        - directory/* 目录中的所有文件
        - * 当前目录中的所有文件
        - directory/- 目录和其子目录中的所有文件
        - - 当前目录和其子目录中的所有文件
        - <<ALL FILES>>

        `permission java.io.FilePermission "/myapp/-", "read,write,delete";`

        `permission java.io.FilePermission "c:\\myapp\\-", "read,write,delte";`

        `permission java.io.FilePermission "${user.home}${/}-", "read,write"`

        > ${/}相当于${file.separator}

    - SocketPermission: accept, connect, listen, resolve
        - localhost, 空字符串 本机
        - hostname, IPaddress
        - * .domain
        - *
        - :port
        - :port- 大于等于
        - :-port 小于等于
        - :p1-p2

        `permission java.net.SocketPermission "*.xxx.com:8000-8999", "connect";`

    - public abstract class java.security.BasicPermission
        - public final class java.lang.RuntimePermission: createClassLoader, exitVM, setIO
        - Audio
        - Auth
        - AWT
        - Logging
        - Net
        - Property: read, write

            `permission java.util.PropertyPermission "java.vm.*", "read";`

        - Reflected
        - Security
        - Serializable
        - SQL

### 策略

策略文件路径: `C:\Java\jdk1.8.0_241\jre\lib\security\java.policy`

```
grant codeBase "file:${{java.ext.dirs}}/*" {
        permission java.security.AllPermission;
};
```

1. 方法一: 在`java.security`中修改

    ```
    policy.url.1=file:${java.home}/lib/security/java.policy
    policy.url.2=file:${user.home}/.java.policy
    ```

2. 方法二: 启动参数修改: `java -Djava.security.policy=MyApp.policy MyApp`
    - 只使用指定策略: `java -Djava.security.policy==MyApp.policy MyApp`

3. 方法三: 设置系统属性修改: `System.setProperty("java.security.policy", "MyApp.policy");`

### 启用安全管理器

1. 方法一: 启动参数: `java -Djava.security.manager -Djava.security.policy=MyApp.policy MyApp`
2. 方法二: 在main方法中添加: `System.setSecurityManager(new SecurityManager);`


## 对象访问

```java
Object obj = new Object();
```

如果在方法体中

- `Object obj`在Java **栈** 的本地变量表中，作为reference类型。
- `new Object()`在Java **堆** 中形成一块存储Instance Data的结构化内存。
- 在方法区中存放该对象 **类型数据** （对象类型、父类、实现的接口、方法等），在Java堆中包含能查找到这些对象类型数据的地址信息。
    + 句柄方式：Java堆中划分出一块内存作为句柄池，reference中存储对象的句柄地址，句柄中包含对象 **实例数据** 和 **类型数据** 各自的地址。
    + 指针方式：reference直接存储对象地址，在对象实例数据中包含对象 **类型数据** 的指针。


## JVM参数

### 标准参数（-）

- -verbose:gc
- -client 使用Client模式，启动速度快，运行时性能和内存管理效率低，用于开发调试
- -server 使用Server模式，启动速度慢，运行时性能和内存管理效率高，用于生产环境

### 非标准参数（-X）

- -Xss128k 每个线程的栈大小。在相同的物理内存下，每个线程栈越小，可以生成更多线程，但受操作系统一个进程内的线程数限制。
- -Xms20M Java堆初始值
- -Xmx200M Java堆最大值（可以设置与-Xms相同，避免每次GC后重新分配内存）
- -Xmn2g 新生代大小，推荐整个堆大小的3/8

### 非稳定参数（-XX）

- -XX:NewSize=1024m 新生代初始值
- -XX:MaxNewSize=1024m 新生代最大值
- -XX:NewRatio=4 新生代（1个Eden、1个from Survivor和1个to Survivor）与老年代的比值为1:4
- -XX:SurvivorRatio=4 新生代中2个Survivor和Eden的比值为2:4
- -XX:PermSize=10M 方法区初始值
- -XX:MaxPermSize=10M 方法区最大值
- -XX:MaxDirectMemorySize=10M 直接内存
- -XX:+UseParNewGC 设置新生代为并发收集
- -XX:+UseConcMarkSweepGC CMS收集，即老年代为并发收集
- -XX:ParallelGCThreads=20 并发收集线程数，建议与CPU（核）数相等
- -XX:+HeapDumpOnOutOfMemoryError 内存溢出时dump内存快照。
- -XX:HeapDumpPath=./java_pid.hprof Dump堆内存路径
- -XX:+PrintGCDetails 每次GC时打印详细信息
- -XX:+TraceClassLoading, 跟踪类加载过程


## 垃圾回收算法

### 判断方法

1. 引用计数: 主流JVM未使用, 无法处理循环引用
1. 可达性分析: 以GCroot(虚拟机栈中，类静态变量，常量，JNI Native方法引用的对象)作为起始点, 无任何引用链

### 垃圾收集算法

1. 标记清除
1. 复制
1. 标记整理
1. 分代收集


!!! quote "参考链接"
    - [JVM概念简介](https://mp.weixin.qq.com/s/eJSkeDh9JXXJz8_4uMwnRw)
    - [JVM运行时内存](https://mp.weixin.qq.com/s/R8ihNFGZmKtiBxIO8oTdQw)
    - [JVM算法简介](https://mp.weixin.qq.com/s/1H-rPnSj8oagZ_0CYyqXwg)
    - [JVM垃圾收集器](https://mp.weixin.qq.com/s/Et-iAwf6L8zx6R8-ILutJg)
    - [JVM调优实战](https://mp.weixin.qq.com/s/eRPTr7AazXbJ0bg78uKwGg)
