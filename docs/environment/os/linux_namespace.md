# linux_namespace

对于 **进程** 而言，namespace用来隔离资源。

## 分类

名称 | 宏定义 | 隔离的资源
--- | --- | ---
IPC | CLONE_NEWIPC | System V IPC(信号量，消息队列，共享内存)和POSIX message queues
Network | CLONE_NEWNET | Network devices, stacks, ports, etc(网络设备，网络栈，端口)
Mount | CLONE_NEWNS | Mount points(文件系统挂载点)
PID | CLONE_NEWPID | Process IDs(进程编号)
User | CLONE_NEWUSER | User and group IDs(用户和用户组)
UTS | CLONE_NEWUTS | Hostname and NIS domain name(主机名与NIS域名)
Cgroup | CLONE_NEWCGROUP | Cgroup root directory(cgroup根目录)


## 查看当前进程所属的namespace

``` hl_lines="1"
# ll /proc/$$/ns
total 0
dr-x--x--x 2 root root 0 Jul 10 15:17 ./
dr-xr-xr-x 9 root root 0 Jul 10 15:17 ../
lrwxrwxrwx 1 root root 0 Jul 10 15:17 cgroup -> cgroup:[4026531835]
lrwxrwxrwx 1 root root 0 Jul 10 15:17 ipc -> ipc:[4026531839]
lrwxrwxrwx 1 root root 0 Jul 10 15:17 mnt -> mnt:[4026531840]
lrwxrwxrwx 1 root root 0 Jul 10 15:17 net -> net:[4026532101]
lrwxrwxrwx 1 root root 0 Jul 10 15:17 pid -> pid:[4026531836]
lrwxrwxrwx 1 root root 0 Jul 10 15:17 user -> user:[4026531837]
lrwxrwxrwx 1 root root 0 Jul 10 15:17 uts -> uts:[4026531838]
```

???+ note "阻止namespace下所有进程结束后被删除，后续进程可以再加入"
    - 方式1. `/proc/{pid}/ns`中的链接文件被打开，存在文件描述符（fd）
    - 方式2. 挂载`/proc/{pid}/ns/xxx`，如：  
        ```
        touch ~/uts
        sudo mount --bind /proc/$$/ns/uts ~/uts
        ```


## API

- clone(): c lib中创建新进程的同时创建namespace.
- setns(): c lib中将当前进程加入到已有的namespace中。

    ???+ tip
        `docker exec`命令调用`setns()`在已运行的容器中执行新的命令。

- unshare()和unshare命令：**不启动新的进程** 创建并加入新的namespace.

    ???+ note "选项"
        - 使用格式：`unshare [options] <program> [<argument>...]`
        - `-r, --map-root-user`: 映射当前用户到新user namespace中的root，如：  
            ```
            $ whoami
            nick
            $ unshare --user --map-root-user sh -c whoami
            root
            ```

???+ note "API调用"
    - 使用时指定参数：CLONE_NEWIPC、CLONE_NEWNET、CLONE_NEWNS、CLONE_NEWPID、CLONE_NEWUSER、CLONE_NEWUTS、CLONE_NEWCGROUP
    - 多个参数使用 `|` 组合。


???+ quote "参考链接"
    [Linux Namespace : 简介](https://www.cnblogs.com/sparkdev/p/9365405.html)


## user

同一个用户的uid和gid在不同的namespace中可以不同。

namespace可以嵌套（最多32层）。

### 创建user namespace

```bash
# 映射当前用户到新user namespace中的root, 默认映射到nobody(65534)
unshare --user -r /bin/bash
```

### 添加uid映射

- 配置路径：`/proc/{pid}/uid_map`, `/proc/{pid}/gid_map`
- 配置格式：`ID-inside-ns ID-outside-ns length`


???+ quote "参考链接"
    [Linux Namespace : User](https://www.cnblogs.com/sparkdev/p/9462838.html)
