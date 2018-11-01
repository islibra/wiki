# 一、程序计数器

当前线程所执行的字节码的行号指示器，每条线程独立的 **线程私有** 内存空间。 **无OutOfMemoryError。**


# 二、Java虚拟机栈

线程私有。Java **方法** 执行时，创建一个Stack Frame，用于存储 **局部变量** 、操作栈、动态链接、方法出口等信息。
局部变量表主要包含编译期可知的基本数据类型（boolean\byte\char\shor\int\float\long\double）、对象引用（reference）、returnAddress类型（指向字节码指令的地址）。
局部变量表所需的内存空间在编译期间完成分配，运行期间不会改变。
异常：
+ StackOverflowError，请求栈深度大于虚拟机允许的深度。
+ OutOfMemoryError，虚拟机栈动态扩展时无法申请到足够的内存。


# 三、本地方法栈

与Java虚拟机栈相同，为虚拟机使用到的Native方法服务。


# 四、Java堆

所有线程共享的一块内存区域，在虚拟机启动时创建。
存放对象实例和数组。
垃圾回收的主要区域，分为新生代和老年代。
在启动参数中通过-Xmx和-Xms控制。
异常：
+ OutOfMemoryError，堆中没有内存完成实例分配，并且堆无法再扩展。


# 五、方法区

各个线程共享的内存区域。
存储已被虚拟机加载的类信息、常量、静态变量、即时编译器编译后的代码等。
非堆内存Non-Heap。
HotSpot虚拟机的设计团队把GC扩展至方法区，并成为永久代（Permanent Generation）。后续规划搬迁至Native Memory。
垃圾回收较少，主要针对 **常量池和对类型的卸载** 。
异常：
+ OutOfMemoryError，方法区无法满足内存分配需求。


## 运行时常量池

用于存放编译期生成的字面量和符号引用，在类加载后存放到方法区的运行时常量池中。


# 六、直接内存

NIO中引入Channel和Buffer，可以使用Native函数库直接分配 **堆外内存** ，然后通过一个存储在Java堆里面的DirectByteBuffer对象作为这块内存的引用进行操作。
不受Java堆大小限制，受本机总内存（RAM、SWAP区或分页文件）大小及处理器寻址空间限制。


# 对象访问

```java
Object obj = new Object();
```

如果在方法体中，`Object obj`在Java栈的本地变量表中，作为reference类型。
`new Object()`在Java堆中形成一块存储Instance Data的结构化内存。
在方法区中存放该对象 **类型数据** （对象类型、父类、实现的接口、方法等），在Java堆中包含能查找到这些对象类型数据的地址信息。
+ 句柄方式：Java堆中划分出一块内存作为句柄池，reference中存储对象的句柄地址，句柄中包含对象 **实例数据** 和 **类型数据** 各自的地址。
+ 指针方式：reference直接存储对象地址，在对象实例数据中包含对象 **类型数据** 的指针。


# JVM参数

## 标准参数（-）

-verbose:gc
-client 使用Client模式，启动速度快，运行时性能和内存管理效率低，用于开发调试
-server 使用Server模式，启动速度慢，运行时性能和内存管理效率高，用于生产环境


## 非标准参数（-X）

-Xms20M Java堆初始值
-Xmx200M Java堆最大值（可以设置与-Xms相同，避免每次GC后重新分配内存）
-Xmn2g 新生代大小，推荐整个堆大小的3/8
-Xss128k 每个线程的栈大小。在相同的物理内存下，每个线程栈越小，可以生成更多线程，但受操作系统一个进程内的线程数限制。


## 非稳定参数（-XX）

-XX:NewSize=1024m 新生代初始值
-XX:MaxNewSize=1024m 新生代最大值
-XX:NewRatio=4 新生代（1个Eden、1个from Survivor和1个to Survivor）与老年代的比值为1:4
-XX:SurvivorRatio=4 新生代中2个Survivor和Eden的比值为2:4
-XX:PermSize=10M 方法区初始值
-XX:MaxPermSize=10M 方法区最大值
-XX:MaxDirectMemorySize=10M 直接内存
-XX:+UseParNewGC 设置新生代为并发收集
-XX:+UseConcMarkSweepGC CMS收集，即老年代为并发收集
-XX:ParallelGCThreads=20 并发收集线程数，建议与CPU（核）数相等
-XX:+HeapDumpOnOutOfMemoryError 内存溢出时dump内存快照。
-XX:HeapDumpPath=./java_pid.hprof Dump堆内存路径
-XX:+PrintGCDetails 每次GC时打印详细信息
