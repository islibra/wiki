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

??? note "阻止namespace下所有进程结束后被删除，后续进程可以再加入"
    - 方式1. `/proc/{pid}/ns`中的链接文件被打开，存在文件描述符（fd）
    - 方式2. 挂载`/proc/{pid}/ns/xxx`，如：  
        ```
        touch ~/uts
        sudo mount --bind /proc/$$/ns/uts ~/uts
        ```


## API

???+ note "API调用"
    - 使用时指定参数：CLONE_NEWIPC、CLONE_NEWNET、CLONE_NEWNS、CLONE_NEWPID、CLONE_NEWUSER、CLONE_NEWUTS、CLONE_NEWCGROUP
    - 多个参数使用 `|` 组合。

- clone(): c lib中创建新进程的同时创建namespace.
- setns(): c lib中将当前进程加入到已有的namespace中。

    ???+ tip
        `docker exec`命令调用`setns()`在已运行的容器中执行新的命令。

- unshare()和unshare命令：**不启动新的进程** 创建并加入新的namespace.

    ???+ note "选项"
        - 使用格式：`unshare [options] <program> [<argument>...]`
        - `-r, --map-root-user`: 映射当前用户到新user namespace中的root，如：  
            ```bash hl_lines="20 22 24"
            # 当前用户
            islibra@SZX1000451827:/proc/15787/ns$ id
            uid=1002(islibra) gid=1002(islibra) groups=1002(islibra)
            # 当前进程ID
            islibra@SZX1000451827:/proc/15787/ns$ echo $$
            15787
            # 当前进程所属namespace
            islibra@SZX1000451827:/proc/15787/ns$ ls -al /proc/$$/ns
            total 0
            dr-x--x--x 2 islibra islibra 0 Jul 11 08:58 .
            dr-xr-xr-x 9 islibra islibra 0 Jul 11 08:56 ..
            lrwxrwxrwx 1 islibra islibra 0 Jul 11 08:58 cgroup -> cgroup:[4026531835]
            lrwxrwxrwx 1 islibra islibra 0 Jul 11 08:58 ipc -> ipc:[4026531839]
            lrwxrwxrwx 1 islibra islibra 0 Jul 11 08:58 mnt -> mnt:[4026531840]
            lrwxrwxrwx 1 islibra islibra 0 Jul 11 08:58 net -> net:[4026532101]
            lrwxrwxrwx 1 islibra islibra 0 Jul 11 08:58 pid -> pid:[4026531836]
            lrwxrwxrwx 1 islibra islibra 0 Jul 11 08:58 user -> user:[4026531837]
            lrwxrwxrwx 1 islibra islibra 0 Jul 11 08:58 uts -> uts:[4026531838]
            # 创建新的namespace并映射root用户
            islibra@SZX1000451827:/proc/15787/ns$ unshare --user -r sh -c "id;echo $$;ls -al /proc/$$/ns"
            # 新namespace中的用户
            uid=0(root) gid=0(root) groups=0(root)
            # 进程ID不改变
            15787
            # 无法跨namespace访问
            ls: cannot read symbolic link '/proc/15787/ns/net': Permission denied
            ls: cannot read symbolic link '/proc/15787/ns/uts': Permission denied
            ls: cannot read symbolic link '/proc/15787/ns/ipc': Permission denied
            ls: cannot read symbolic link '/proc/15787/ns/pid': Permission denied
            ls: cannot read symbolic link '/proc/15787/ns/user': Permission denied
            ls: cannot read symbolic link '/proc/15787/ns/mnt': Permission denied
            ls: cannot read symbolic link '/proc/15787/ns/cgroup': Permission denied
            total 0
            dr-x--x--x 2 root root 0 Jul 11 08:58 .
            dr-xr-xr-x 9 root root 0 Jul 11 08:56 ..
            lrwxrwxrwx 1 root root 0 Jul 11 08:58 cgroup
            lrwxrwxrwx 1 root root 0 Jul 11 08:58 ipc
            lrwxrwxrwx 1 root root 0 Jul 11 08:58 mnt
            lrwxrwxrwx 1 root root 0 Jul 11 08:58 net
            lrwxrwxrwx 1 root root 0 Jul 11 08:58 pid
            lrwxrwxrwx 1 root root 0 Jul 11 08:58 user
            lrwxrwxrwx 1 root root 0 Jul 11 08:58 uts
            # sh -c 执行结束后，新的namespace自动删除
            islibra@SZX1000451827:/proc/15787/ns$ id
            uid=1002(islibra) gid=1002(islibra) groups=1002(islibra)
            ```


???+ quote "参考链接"
    [Linux Namespace : 简介](https://www.cnblogs.com/sparkdev/p/9365405.html)


## user

同一个用户的uid和gid在不同的namespace中可以不同，通过映射关系对应。

namespace可以嵌套（最多32层）。

### 创建user namespace

???+ fail
    - 在Linux 3.10.0版本中调用`unshare --user -r /bin/bash`报错`unshare failed: Invalid argument`，{==Linux 3.10.0版本不支持user namespace==}。
    - 在Ubuntu Linux 4.4.0中正常。

```bash hl_lines="6 17"
islibra@SZX1000451827:/proc/15787/ns$ id
uid=1002(islibra) gid=1002(islibra) groups=1002(islibra)
islibra@SZX1000451827:/proc/15787/ns$ echo $$
15787
islibra@SZX1000451827:/proc/15787/ns$ readlink user
user:[4026531837]
# 创建新的namespace并启动新的bash
islibra@SZX1000451827:/proc/15787/ns$ unshare --user -r /bin/bash
root@SZX1000451827:/proc/15787/ns# id
uid=0(root) gid=0(root) groups=0(root)
# 进程ID
root@SZX1000451827:/proc/15787/ns# echo $$
21730
# 新的namespace ID
root@SZX1000451827:/proc/15787/ns# cd /proc/$$/ns
root@SZX1000451827:/proc/21730/ns# readlink user
user:[4026532317]
# 进程ID关系
root@SZX1000451827:/proc/21730/ns# ps -efw | grep 21730
root      21730  15787  0 09:32 pts/0    00:00:00 /bin/bash
root      21903  21730  0 09:33 pts/0    00:00:00 ps -efw
root      21904  21730  0 09:33 pts/0    00:00:00 grep 21730
```

### 添加uid映射

- 配置路径：`/proc/{pid}/uid_map`, `/proc/{pid}/gid_map`, pid为新的namespace中新的进程ID
- 配置格式：`ID-inside-ns ID-outside-ns length`

```bash tab="自动映射到root" hl_lines="10"
islibra@SZX1000451827:/proc/15787/ns$ id
uid=1002(islibra) gid=1002(islibra) groups=1002(islibra)
# 映射当前用户到新user namespace中的root
islibra@SZX1000451827:/proc/15787/ns$ unshare --user -r /bin/bash
root@SZX1000451827:/proc/15787/ns# id
uid=0(root) gid=0(root) groups=0(root)
root@SZX1000451827:/proc/15787/ns# cd /proc/$$
# 将新namespace中的root(0)映射到外层的islibra(1002)
root@SZX1000451827:/proc/21730# cat uid_map
         0       1002          1
```

```bash tab="默认并手动添加映射" hl_lines="9 12 27"
# 默认映射到nobody(65534)
islibra@SZX1000451827:/proc$ unshare --user /bin/bash
nobody@SZX1000451827:/proc$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
nobody@SZX1000451827:/proc$ echo $$
29378

# 需要使用创建新namespace的用户并为bash添加权限
root@SZX1000451827:/proc/29378# setcap cap_setgid,cap_setuid+ep /bin/bash
root@SZX1000451827:/proc/29378# getcap /bin/bash
/bin/bash = cap_setgid,cap_setuid+ep
root@SZX1000451827:/proc/29378# su - islibra
islibra@SZX1000451827:~$ cd /proc/29378
islibra@SZX1000451827:/proc/29378$ cat uid_map
islibra@SZX1000451827:/proc/29378$ echo '0 1002 1' > uid_map
islibra@SZX1000451827:/proc/29378$ echo '0 1002 1' > gid_map
islibra@SZX1000451827:/proc/29378$ exit
logout
root@SZX1000451827:/proc/29378# setcap cap_setgid,cap_setuid-ep /bin/bash
root@SZX1000451827:/proc/29378# getcap /bin/bash
/bin/bash =
# 重新加载bash
nobody@SZX1000451827:/proc$ exec bash
root@SZX1000451827:/proc# id
uid=0(root) gid=0(root) groups=0(root)
root@SZX1000451827:/proc# cat /proc/$$/uid_map
         0       1002          1
```

???+ tip "实际在/etc/subuid配置了从属用户"
    ```bash
    root@SZX1000451827:~# cat /etc/subuid
    root:100000:65536
    # 将子user namespace中的0-65535映射为当前namespace中的165536-231071
    islibra:165536:65536
    ```

???+ warning "无法访问原namespace中的数据，即使映射为同一个用户"
    ```bash hl_lines="2 4"
    root@SZX1000451827:~# cd /root
    bash: cd: /root: Permission denied
    root@SZX1000451827:~# ls -al / | grep root
    drwx------  11 nobody nogroup  4096 Jul 11 10:03 root
    ```


???+ quote "参考链接"
    [Linux Namespace : User](https://www.cnblogs.com/sparkdev/p/9462838.html)
