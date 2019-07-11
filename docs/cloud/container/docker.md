# docker

![language](https://img.shields.io/badge/language-Go-brightgreen.svg)

!!! tip "Docker版本"
    Docker官方版本从 {==1.13.x==} 开始，一跃到 {==17.03==}。  
    之后每月发布一个edge版本，如17.03, 17.04, 17.05...，每三个月发布一个stable版本，如17.03, 17.06, 17.09...

## uid

???+ warning
    docker默认 **以root启动容器**，容器中的进程默认以 {==root==} 运行，且 {==与host共用一套uid==}。

    即容器中的root和host上的root是同一个用户。

    ```bash
    # host用户user namespace
    [root@nodelee-9781500-562d15f5 docker]# readlink /proc/$$/ns/user
    user:[4026531837]

    # 查看容器进程
    [root@nodelee-9781500-562d15f5 docker]# docker ps
    CONTAINER ID        IMAGE                                                    COMMAND                  CREATED             STATUS              PORTS               NAMES
    68dc8b591280        100.125.0.82:20202/repospacelee/c-dos:latest             "/bin/sh -c '/usr/loc"   45 hours ago        Up 45 hours                             k8s_ccc_ccc-764d668fb7-6jdmx_5c7ee98de81c45c389d1f3b91509253d_db398091-a252-11e9-9ecb-fa163e93fafa_0

    [root@nodelee-9781500-562d15f5 docker]# docker top 68dc8b591280
    UID                 PID                 PPID                C                   STIME               TTY                 TIME                CMD
    root                27123               27104               0                   Jul09               ?                   00:00:00            /bin/sh -c /usr/local/apache-tomcat-7.0.82/bin/startup.sh && tail -F /usr/local/apache-tomcat-7.0.82/logs/catalina.out

    # 根据容器进程ID查看user namespace
    [root@nodelee-9781500-562d15f5 docker]# readlink /proc/27123/ns/user
    user:[4026531837]

    # 进入容器查看user namespace
    [root@nodelee-9781500-562d15f5 docker]# docker exec -it 68dc8b591280 bash
    root@ccc-764d668fb7-6jdmx:/# readlink /proc/$$/ns/user
    user:[4026531837]
    ```


### 指定容器中的运行用户

#### Dockerfile

```
FROM ubuntu
# host上已存在则不需要再创建，否则会报UID 1000 is not unique
RUN useradd -r -u 1000 -g 1000 islibra
USER 1000
ENTRYPOINT ["sleep", "infinity"]
```

构建镜像：`docker build -t test .`

启动容器：`docker run -d --name sleepme test`

查看容器运行用户（islibra在host上的UID为1000）：  
```bash
[root@nodelee-9781500-562d15f5 ~]# ps -efw | grep sleep
islibra     22876 22857  0 21:02 ?        00:00:00 sleep infinity
[root@nodelee-9781500-562d15f5 ~]# docker exec -it cc09fab33625 bash
[islibra@cc09fab33625 /]$ whoami
islibra
[islibra@cc09fab33625 /]$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
islibra:x:1000:1000::/home/islibra:/bin/bash
```

#### docker run --user

```bash
[root@nodelee-9781500-562d15f5 ~]# docker run -d --user 1000 --name sleepme ubuntu sleep infinity
[root@nodelee-9781500-562d15f5 ~]# ps -efw | grep sleep
islibra     22876 22857  0 21:02 ?        00:00:00 sleep infinity
```

???+ info "使用--user会覆盖Dockerfile中的值"
    ```bash hl_lines="4 9"
    [root@nodelee-9781500-562d15f5 ~]# docker run -d test
    0f6a94100f90cf7d35a21c06d188661d25f4ab408830be673d5130e3f9bc4e7e
    [root@nodelee-9781500-562d15f5 ~]# ps -efw | grep sleep
    islibra     22510 22490  0 21:28 ?        00:00:00 sleep infinity
    [root@nodelee-9781500-562d15f5 ~]# docker run -d --user 0 test
    e1f19977e4d9905331791063a416665b791d1b4c78d38b34171d60b7b293427b
    [root@nodelee-9781500-562d15f5 ~]# ps -efw | grep sleep
    islibra     22510 22490  0 21:28 ?        00:00:00 sleep infinity
    root     24558 24539  1 21:28 ?        00:00:00 sleep infinity
    ```


???+ quote "参考链接"
    [理解 docker 容器中的 uid 和 gid](https://www.cnblogs.com/sparkdev/p/9614164.html)


### 启用Linux user namespace对容器中的用户隔离

#### 手动

1. 创建用户`dockeruser`并在`/etc/subuid`中增加映射  
```
root:100000:65536
dockeruser:165536:65536
```
1. 修改`/etc/docker/daemon.json`  
```
{
    "userns-remap": "dockeruser"
}
```

#### 自动

修改`/etc/docker/daemon.json`  
```
{
    "userns-remap": "default"
}
```

---

重启docker: `systemctl restart docker.service`

#### 验证

```bash hl_lines="5 11 15 18 24 34 38 42"
root@SZX1000451827:/etc/docker# cat /etc/passwd
root:x:0:0:hostroot:/root:/bin/bash
...
# 自动创建dockermap用户
dockremap:x:110:115::/home/dockremap:/bin/false

root@SZX1000451827:/etc/docker# cat /etc/subuid
root:100000:65536
...
# 自动添加从属映射
dockremap:362144:65536

# 在/var/lib/docker自动创建362144.362144目录，内容与/var/lib/docker相同
root@SZX1000451827:/var/lib/docker# ls
362144.362144  aufs  containers  image  network  plugins  swarm  tmp  trust  volumes
root@SZX1000451827:/var/lib/docker# cd 362144.362144/
root@SZX1000451827:/var/lib/docker/362144.362144# ls
aufs  containers  image  network  plugins  swarm  tmp  trust  volumes

# 启动容器，进程以362144运行
root@SZX1000451827:~# docker run -d --name sleepme ubuntu sleep infinity
a24c65edf9c9931820d6a0b68ed34e506efaf874493d2255916da7f4486d8910
root@SZX1000451827:~# ps -efw | grep sleep
362144   115876 115858  0 19:13 ?        00:00:00 sleep infinity

# 进入容器，内部以root(0)运行
root@SZX1000451827:~# docker ps -a
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
a24c65edf9c9        euleros:2.2.5       "sleep infinity"    3 seconds ago       Up 2 seconds                            sleepme
root@SZX1000451827:~# docker exec -it a24c65edf9c9 bash
[root@a24c65edf9c9 /]# id
uid=0(root) gid=0(root) groups=0(root)
[root@a24c65edf9c9 /]# ps -efw | grep sleep
root          1      0  0 11:13 ?        00:00:00 sleep infinity

# 查看user namespace
[root@a24c65edf9c9 /]# readlink /proc/$$/ns/user
user:[4026532319]

# 查看映射
[root@a24c65edf9c9 /]# cat /proc/$$/uid_map
         0     362144      65536
```

#### 禁用

```bash
root@SZX1000451827:~# docker run -d --userns=host --name sleepyou ubuntu sleep infinity
eabaf65e94ac6558865c9ca1002ee30ca5b873f7d669b919b6db9f3ae5853732
root@SZX1000451827:~# ps -efw | grep sleep
root     118482 118445  0 19:26 ?        00:00:00 sleep infinity
root@SZX1000451827:~# readlink /proc/$$/ns/user
user:[4026531837]
root@SZX1000451827:~# readlink /proc/118482/ns/user
user:[4026531837]
```


???+ quote "参考链接"
    [隔离 docker 容器中的用户](https://www.cnblogs.com/sparkdev/p/9614326.html)


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
