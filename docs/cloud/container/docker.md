# docker

![language](https://img.shields.io/badge/language-Go-brightgreen.svg)

!!! tip "Docker版本"
    Docker官方版本从 {==1.13.x==} 开始，一跃到 {==17.03==}。  
    之后每月发布一个edge版本，如17.03, 17.04, 17.05...，每三个月发布一个stable版本，如17.03, 17.06, 17.09...

## uid

???+ warning
    容器和host共享一套uid/gid, 容器中的进程默认以 {==root==} 运行。

## docker run

命令格式：`docker run [OPTIONS] IMAGE [COMMAND] [ARG...]`

???+ note "OPTIONS"
    - `-d, --detach`, 后台运行容器并打印容器ID。
    - `-u, --user`, 指定 {==容器中==} 的Username或UID，格式：`<name|uid>[:<group|gid>]`
    - `--rm`, 容器退出时自动删除。
    - `--ulimit <type>=<soft limit>[:<hard limit>]`, 如`$ docker run --ulimit nofile=1024:1024 --rm debian sh -c "ulimit -n"`, 限制打开文件数。
        - 如果未设置`hard limit`, 以`soft limit`为准。
        - **如果未设置，继承自daemon默认值。**
        - **docker对设置值不做任何转换，直接传递给linux系统调用。**

    ???+ warning "nproc"
        使用`--ulimit nproc` {==针对的是用户==} 设置最大进程数，而非容器。

???+ quote "参考链接"
    [docker docs](https://docs.docker.com/engine/reference/commandline/run/)


## 常用命令

- 查看容器进程ID
    1. 使用`docker ps`获取`CONTAINER ID`
    1. 使用`docker top {CONTAINER ID}`获取`PID, PPID`
    1. 使用`ps -efw | grep -v grep | grep {PID}`查看进程。


---
以下未整理
---

!!! info
    - Docker Daemon以 {==root==} 权限运行。
    - 相比于VM需要在hostOS上安装hypervisor和guestOS，Docker Engine直接运行在hostOS上，其上跑APP。
    - 存在未namespaces隔离资源，如`/proc, /sys, top, free, root, /dev, 内核...`
    - 所有运行的容器 {==共享==} host内核，通过容器内系统崩溃 --> 内核崩溃 --> 其他容器崩溃。


```bash
docker cp file.xxx ced60ce33136:/opt/xxx  #将host上的文件拷贝到容器

docker images  #查看已存在的镜像
docker save b0f6bcd0a2a0 > file.tar  #将镜像导出为文件
docker rmi b0f6bcd0a2a0  #删除已存在的镜像
docker load < file.tar  #镜像导入
docker tag b0f6bcd0a2a0 euleros:2.2.5  #为导入的镜像打标签

docker ps  #查看正在运行的容器
docker export b91d9ad83efa > file.tar  #将容器导出
docker import file.tar  #将容器导入
```
