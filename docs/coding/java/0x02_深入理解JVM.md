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

Java虚拟机把描述类的数据, 从class文件加载到内存(方法区), 并对数据进行校验、转换解析和初始化，最终形成可被虚拟机直接使用的Java类型

运行期间进行

!!! example "编写一个面向接口的应用, 运行时通过Java预置或 {==自定义的类加载器==}, 从网络加载一个 {==二进制字节流==}作为实际的实现类"

### 1. 加载(Loading)

### 2. 连接(Linking)

#### a. 验证(Verification)

#### b. 准备(Preparation)

#### c. 解析(Resolution)

### 3. 初始化(Initialization)

1. 虚拟机启动时, 初始化包含main()的主类
1. 由new, getstatic, putstatic, invokestatic指令触发

    - 使用new关键字实例化对象
    - 读取或设置类静态字段

        > 被final修饰的常量, 已在编译期间把结果放入常量池

    - 调用类静态方法

1. 初始化类的时候, 如果其父类还没有初始化
1. 使用java.lang.reflect包的方法对类进行反射调用的时候
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

        !!! tip "会触发[Lxxx.SuperClass的类初始化"

### 4. 使用(Using)

### 5. 卸载(Unloading)


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
