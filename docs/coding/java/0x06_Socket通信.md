# 0x06_Socket通信

## BIO

示例代码（服务端）：

```java
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class AaronServer extends Thread {

    private ServerSocket serverSocket;

    public AaronServer(int port) {
        try {
            serverSocket = new ServerSocket(port);
            serverSocket.setSoTimeout(10000);
        } catch (IOException e) {
            System.out.println(e);
        }
    }

    public void run() {
        while(true) {
            System.out.println("waiting for client on port " + serverSocket.getLocalPort() + "...");
            try {
                Socket socket = serverSocket.accept();
                System.out.println("just connected to " + socket.getRemoteSocketAddress());
                DataInputStream in = new DataInputStream(socket.getInputStream());
                System.out.println(in.readUTF());

                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                out.writeUTF("Thank u for connect to " + socket.getLocalSocketAddress());
                socket.close();
            } catch (IOException e) {
                System.out.println(e);
            }
        }
    }

    public static void main(String[] args) {
        Thread t = new AaronServer(6066);
        t.start();
    }
}
```

示例代码（客户端）：

```java
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

public class AaronClient {

    public static void main(String[] args) {
        System.out.println("connecting to aaron on port 6066...");
        try {
            Socket client = new Socket("127.0.0.1", 6066);
            System.out.println("just connected to " + client.getRemoteSocketAddress());
            DataOutputStream out = new DataOutputStream(client.getOutputStream());
            out.writeUTF("hello from " + client.getLocalSocketAddress());

            DataInputStream in = new DataInputStream(client.getInputStream());
            System.out.println("server say: " + in.readUTF());
            client.close();
        } catch (IOException e) {
            System.out.println(e);
        }
    }

}
```

## 多线程

示例代码（服务端）：

```java
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MyServer {

    private static ExecutorService executorService = Executors.newCachedThreadPool();

    private static class HandleMsg implements Runnable{
        Socket client;
        public HandleMsg(Socket client){
            this.client = client;
        }
        @Override
        public void run() {
            BufferedReader bufferedReader = null;
            PrintWriter printWriter = null;
            try {
                bufferedReader = new BufferedReader(new InputStreamReader(client.getInputStream()));
                printWriter = new PrintWriter(client.getOutputStream(),true);
                String inputLine = null;
                long a = System.currentTimeMillis();
                while ((inputLine = bufferedReader.readLine())!=null){
                    printWriter.println(inputLine);
                }
                long b = System.currentTimeMillis();
                System.out.println("Thread cost: " + (b-a) + " seconds.");
            } catch (IOException e) {
                System.out.println(e);
            }finally {
                try {
                    bufferedReader.close();
                    printWriter.close();
                    client.close();
                } catch (IOException e) {
                    System.out.println(e);
                }
            }
        }
    }

    public static void main(String[] args) throws IOException {
        ServerSocket server = new ServerSocket(8686);
        Socket client = null;
        while (true){
            client = server.accept();
            System.out.println(client.getRemoteSocketAddress()+" client connect success.");
            executorService.submit(new HandleMsg(client));
        }
    }

}
```

示例代码（客户端）：

```java
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;

public class MyClient {

    public static void main(String[] args) throws IOException {
        Socket client = null;
        PrintWriter printWriter = null;
        BufferedReader bufferedReader = null;
        try {
            client = new Socket();
            client.connect(new InetSocketAddress("localhost",8686));
            printWriter = new PrintWriter(client.getOutputStream(),true);
            printWriter.println("hello");
            printWriter.flush();

            bufferedReader = new BufferedReader(new InputStreamReader(client.getInputStream()));
            System.out.println("The message from server is: "+bufferedReader.readLine());
        } catch (IOException e) {
            System.out.println(e);
        }finally {
            printWriter.close();
            bufferedReader.close();
            client.close();
        }
    }

}
```


## NIO

### 核心要素

#### Buffer，缓冲区

Buffer类型: Byte Char Int long short double float

数据流向：`Client <-data-> Buffer <-data-> Channel <-data-> Channel <-data-> Buffer <-data-> Server`

+ 分配空间：`ByteBuffer byteBuffer = ByteBuffer.allocate(1024);`
+ 从Client向Buffer中写入数据：`byteBuffer.put(...);`
+ 获取Channel：`inputstream.getchanel();`
+ Buffer中的数据写入Channel：`channel.write(byteBuffer);`
+ 读写转换：`bytebuffer.flip();`
+ Buffer从Channel中读取数据：`channel.read(byteBuffer);`
+ Server从Buffer中读取数据：`byteBuffer.get(...);`


> + capacity，缓冲区容量
> + position，当前位置，下一次读取和写入的索引
> + limit，界限，最后一个有效位置之后的下一个位置的索引
> + flip()，将limit设置为position，position设置为0
> + clear()，清空缓冲区


#### Channel，通道

chanel相对于input/outputstream流来说是双向的。

+ FileChannel，文件IO
+ DatagramChannel，UDP协议
+ ServerSocketChannel/SocketChannel，TCP协议

> 打开一个ServerSocketChannel通道：`ServerSocketChannel serverSocketChannel = ServerSocketChannel.open();`
> 将通道设置为非阻塞：`serverSocketChannel.configureBlocking(false);`
> 循环监听SocketChannel：

```java
while(true){
    SocketChannel socketChannel = serverSocketChannel.accept();
}
```

> 关闭ServerSocketChannel通道：`serverSocketChannel.close();`


#### Selector，选择器，通道管理器，选择器允许一个单独的线程来监视多个通道

> 创建并返回一个选择器实例：`Selector.open();`
> 将通道与选择器绑定并注册一个OP_ACCEPT事件：`SelectionKey selectionKey = channel.register(selector,SelectionKey.OP_ACCEPT);`

> **Tips:** Channel和Selector绑定时，Channel必须是非阻塞模式，而FileChannel不能切换到非阻塞模式，因为它不是套接字通道，所以FileChannel不能和Selector绑定事件。

> 1. SelectionKey.OP_CONNECT：连接事件
> 2. SelectionKey.OP_ACCEPT：接收事件
> 3. SelectionKey.OP_READ：读事件
> 4. SelectionKey.OP_WRITE：写事件

> 轮询

```java
while (true){
    selector.select();  //这是一个阻塞方法，一直等待直到有数据可读，返回值是SelectionKey的数量
    Set keys = selector.selectedKeys();  //如果channel有数据了，获取keys集合
    Iterator iterator = keys.iterator();
    while (iterator.hasNext()){
        SelectionKey key = (SelectionKey) iterator.next();
        iterator.remove();
        if (key.isAcceptable()){
            doAccept(key);
        } else...
    }
}
```

> SelectionKey对象，检测Channel事件类型

```java
selectionKey.isAcceptable();
selectionKey.isConnectable();
selectionKey.isReadable();
selectionKey.isWritable();
```

> 通过SelectionKey获取Channel和Selector

```java
Channel  channel  = selectionKey.channel();
Selector selector = selectionKey.selector();
```

> 在Channel上注册事件并绑定一个Buffer：`clientChannel.register(key.selector(), SelectionKey.OP_READ,ByteBuffer.allocateDirect(1024));`
> 绑定一个Object：

```java
selectionKey.attach(Object);
Object anthorObj = selectionKey.attachment();
```

### 示例代码

#### 服务端

```java
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Set;

public class MyNioServer {
    private Selector selector;
    private final static int port = 8686;
    private final static int BUF_SIZE = 10240;

    private void initServer() throws IOException {
        this.selector=Selector.open();

        ServerSocketChannel channel = ServerSocketChannel.open();
        channel.configureBlocking(false);
        channel.socket().bind(new InetSocketAddress(port));

        SelectionKey selectionKey = channel.register(selector,SelectionKey.OP_ACCEPT);

        while (true){
            selector.select();
            Set keys = selector.selectedKeys();
            Iterator iterator = keys.iterator();
            while (iterator.hasNext()){
                SelectionKey key = (SelectionKey) iterator.next();
                iterator.remove();
                if (key.isAcceptable()){
                    doAccept(key);
                }else if (key.isReadable()){
                    doRead(key);
                }else if (key.isWritable() && key.isValid()){
                    doWrite(key);
                }else if (key.isConnectable()){
                    System.out.println("Connect success.");
                }
            }
        }
    }

    public void doAccept(SelectionKey key) throws IOException {
        ServerSocketChannel serverChannel = (ServerSocketChannel) key.channel();
        System.out.println("ServerSocketChannel is listening...");
        SocketChannel clientChannel = serverChannel.accept();
        clientChannel.configureBlocking(false);
        clientChannel.register(key.selector(),SelectionKey.OP_READ);
    }

    public void doRead(SelectionKey key) throws IOException {
        SocketChannel clientChannel = (SocketChannel) key.channel();
        ByteBuffer byteBuffer = ByteBuffer.allocate(BUF_SIZE);
        long bytesRead = clientChannel.read(byteBuffer);
        while (bytesRead > 0){
            byteBuffer.flip();
            byte[] data = byteBuffer.array();
            String info = new String(data).trim();
            System.out.println("The message from client is " + info);
            byteBuffer.clear();
            bytesRead = clientChannel.read(byteBuffer);
        }
        clientChannel.register(key.selector(), SelectionKey.OP_WRITE);
        /*if (bytesRead == -1){
            clientChannel.close();
        }*/
    }

    public void doWrite(SelectionKey key) throws IOException {
        ByteBuffer byteBuffer = ByteBuffer.allocate(BUF_SIZE);
        String info = "Hello Client.";
        byteBuffer.clear();
        byteBuffer.put(info.getBytes("UTF-8"));
        byteBuffer.flip();
        SocketChannel clientChannel = (SocketChannel) key.channel();
        while (byteBuffer.hasRemaining()){
            clientChannel.write(byteBuffer);
        }
        byteBuffer.compact();
        clientChannel.close();
    }

    public static void main(String[] args) throws IOException {
        MyNioServer myNioServer = new MyNioServer();
        myNioServer.initServer();
    }
}
```

#### 客户端

```java
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Iterator;

public class MyNioClient {
    private Selector selector;
    private final static int port = 8686;
    private final static int BUF_SIZE = 10240;
    private static ByteBuffer byteBuffer = ByteBuffer.allocate(BUF_SIZE);

    private void  initClient() throws IOException {
        this.selector = Selector.open();
        SocketChannel clientChannel = SocketChannel.open();
        clientChannel.configureBlocking(false);
        clientChannel.connect(new InetSocketAddress(port));
        clientChannel.register(selector, SelectionKey.OP_CONNECT);
        while (true){
            selector.select();
            Iterator<SelectionKey> iterator = selector.selectedKeys().iterator();
            while (iterator.hasNext()){
                SelectionKey key = iterator.next();
                iterator.remove();
                if (key.isConnectable()){
                    doConnect(key);
                }else if (key.isReadable()){
                    doRead(key);
                }
            }
        }
    }

    public void doConnect(SelectionKey key) throws IOException {
        SocketChannel clientChannel = (SocketChannel) key.channel();
        if (clientChannel.isConnectionPending()){
            clientChannel.finishConnect();
        }
        clientChannel.configureBlocking(false);
        String info = "Hello Server.";
        byteBuffer.clear();
        byteBuffer.put(info.getBytes("UTF-8"));
        byteBuffer.flip();
        clientChannel.write(byteBuffer);
        clientChannel.register(key.selector(),SelectionKey.OP_READ);
        //clientChannel.close();
    }

    public void doRead(SelectionKey key) throws IOException {
        SocketChannel clientChannel = (SocketChannel) key.channel();
        byteBuffer.clear();
        clientChannel.read(byteBuffer);
        byteBuffer.flip();
        byte[] data = byteBuffer.array();
        String msg = new String(data).trim();
        System.out.println("Received message from server: " + msg);
        clientChannel.close();
        //key.selector().close();
    }

    public static void main(String[] args) throws IOException {
        MyNioClient myNioClient = new MyNioClient();
        myNioClient.initClient();
    }
}
```


!!! quote "参考链接：[Java NIO详解](https://segmentfault.com/a/1190000012316621)"


## AIO

!!! tip "AIO需要操作系统支持"

### 核心类

+ AsynchronousChannelGroup

    ```java
    //使用线程池初始化AsynchronousChannelGroup
    ExecutorService executorService = Executors.newFixedThreadPool(80);  //处理IO事件和触发CompletionHandler回调接口
    AsynchronousChannelGroup channelGroup = AsynchronousChannelGroup.withThreadPool(executorService);
    ```

+ AsynchronousServerSocketChannel

    ```java
    //使用group初始化server socket
    AsynchronousServerSocketChannel serverChannel = AsynchronousServerSocketChannel.open(channelGroup);
    setOption(SocketOption<T> name, T value)  //配置Socket参数
    serverChannel.bind(new InetSocketAddress(ip, port), 100);  //backlog参数指定队列中挂起的连接的最大个数
    ```

    - 方法一、通过返回Future的get方法接收客户端请求

        ```java
        Future<AsynchronousSocketChannel> accept();
        ```

        ```java
        while (true){
            Future<AsynchronousSocketChannel> future = serverSocketChannel.accept();
            AsynchronousSocketChannel socketChannel = null;
            try {
                socketChannel = future.get();
                socketChannel.write(ByteBuffer.wrap("ssss".getBytes("UTF-8")));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        ```

    - 方法二、通过回调方法接收客户端请求

        ```java
        <A> void accept(A attachment ,CompletionHandler<AsynchronousSocketChannel,? super A> handler)  
        //CompletionHandler定义两个方法：
        completed(V result , A attachment)  //参数：IO操作返回的对象AsynchronousSocketChannel， 发起IO操作时传入的附加参数
        faild(Throwable exc, A attachment)  //参数：IO操作失败引发的异常或错误， 发起IO操作时传入的附加参数
        ```

        ```java
        server.accept(null, new CompletionHandler<AsynchronousSocketChannel, Object>() {
            final ByteBuffer buffer = ByteBuffer.allocate(1024);  

            @Override  
            public void completed(AsynchronousSocketChannel result, Object attachment) {  
                System.out.println("waiting....");  
                buffer.clear();  
                try {  
                    //把socket中的数据读取到buffer中  
                    result.read(buffer).get();  
                    buffer.flip();  
                    System.out.println("Echo " + new String(buffer.array()).trim() + " to " + result);  

                    //把收到的直接返回给客户端  
                    result.write(buffer);  
                    buffer.flip();  
                } catch (InterruptedException e) {  
                    e.printStackTrace();  
                } catch (ExecutionException e) {  
                    e.printStackTrace();  
                } finally {  
                    try {  
                        //关闭处理完的socket，并重新调用accept等待新的连接  
                        result.close();  
                        server.accept(null, this);  
                    } catch (IOException e) {  
                        e.printStackTrace();  
                    }  
                }  
            }  

            @Override  
            public void failed(Throwable exc, Object attachment) {  
                System.out.print("Server failed...." + exc.getCause());  
            }  
        });
        ```

+ AsynchronousSocketChannel
    + connect()  用于连接到指定IP/端口的服务器
    + read()
    + write()


## 框架

!!! quote "参考链接"
    - [再有人问你Netty是什么，就把这篇文章发给他](https://mp.weixin.qq.com/s?__biz=MzAxNjk4ODE4OQ==&mid=2247485182&idx=1&sn=f9e3fb858cd8dc6c91a7297aeab2c28a&chksm=9bed278cac9aae9ae2b6d80cb4a0adc4cc59888cdb9e4f6d9f5184787ac2cfb8149418f32a5b&scene=0&subscene=131&clicktime=1551314943&ascene=7&devicetype=android-26&version=2700033a&nettype=WIFI&abtest_cookie=BQABAAgACgALABIAEwAFAJ6GHgAjlx4AWpkeAMKZHgDZmR4AAAA%3D&lang=zh_CN&pass_ticket=OKuO82d079uqfErorTOpzk8hBVZcU%2FD07Zu1kqktASXD98Q6dc%2BBnDvT8sEUej0L&wx_header=1)
    - [跟着狼哥学高性能框架Netty](https://mp.weixin.qq.com/s/nVqjSbocs4kFFz2pJqovhQ)
