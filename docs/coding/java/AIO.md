---
title: AIO
date: 2018-09-08 11:54:02
categories: java
tags:
---

AIO需要操作系统支持.


# 核心类

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

Future<AsynchronousSocketChannel> accept()  //通过返回Future的get方法接收客户端请求
//示例代码
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

<A> void accept(A attachment ,CompletionHandler<AsynchronousSocketChannel,? super A> handler)  //通过回调方法接收客户端请求
//CompletionHandler定义两个方法：
completed(V result , A attachment)  //参数：IO操作返回的对象AsynchronousSocketChannel， 发起IO操作时传入的附加参数
faild(Throwable exc, A attachment)  //参数：IO操作失败引发的异常或错误， 发起IO操作时传入的附加参数
//示例代码
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
