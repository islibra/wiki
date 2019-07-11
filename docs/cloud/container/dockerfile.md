# Dockerfile

**FROM xxx:latest** 指定base镜像

**MAINTAINER xxx** 镜像作者

**ARG xxx=123**

**ENV xxx 123** 设置环境变量。运行容器的时候也生效。

```
ENV MY_VERSION 1.3
RUN apt-get install -y mypackage=$MY_VERSION
```

## 拷贝文件到镜像

### COPY

**COPY** 将文件从build context复制到镜像

``` tab="shell"
COPY src dest
```

``` tab="exec"
COPY ["src", "dest"]
```

### ADD

**ADD xxx /xxx/yyy** 将文件从build context复制到镜像，如果src是归档文件（tar, zip, tgz, xz等），**自动解压** 到dest。

---

**USER xxx** 设置容器中的运行用户或UID。

**WORKDIR "/xxx"** 设置镜像中的当前工作目录。运行容器的时候，会自动进入该目录。


## 执行命令

### RUN

**RUN** 运行命令并 **创建新的镜像层**，常用于 **安装应用和软件包**。

### CMD

**CMD** 容器启动后默认执行的命令及其参数，只有 **最后一个生效** ^推荐Exec格式^

**能被docker run后面跟的命令行参数替换**，如：`docker run -it {image} /bin/bash`。

常用于设置 **默认启动命令**。

### ENTRYPOINT

**ENTRYPOINT** 容器启动后默认执行的命令，只有 **最后一个生效**。

**不会被忽略**。

Docker镜像的用途是 **运行应用程序或服务** 时使用。

``` tab="exec"
# 可使用CMD提供额外的参数
ENTRYPOINT ["/bin/echo", "Hello"]
CMD ["world"]

# 当容器通过 docker run -it [image] 启动时，输出为：
Hello world
# 而如果通过 docker run -it [image] CloudMan 启动，则输出为：
Hello CloudMan
```

``` tab="shell"
忽略任何 CMD 或 docker run 提供的参数。
```


## 两种命令格式

### shell

``` tab="RUN"
RUN apt-get install python3
```

``` tab="CMD"
CMD echo "Hello world"
```

``` tab="ENTRYPOINT"
ENTRYPOINT echo "Hello world"
```

会被shell解析，如：

```
ENV name Cloud Man
ENTRYPOINT echo "Hello, $name"
```

相当于

```
ENV name Cloud Man
ENTRYPOINT ["/bin/sh", "-c", "echo Hello, $name"]
```

### exec

``` tab="RUN"
RUN ["apt-get", "install", "python3"]
```

``` tab="CMD"
CMD ["/bin/echo", "Hello world"]
```

``` tab="ENTRYPOINT"
ENTRYPOINT ["/bin/echo", "Hello world"]
```

不会被shell解析，如：

```
ENV name Cloud Man
ENTRYPOINT ["/bin/echo", "Hello, $name"]
```
