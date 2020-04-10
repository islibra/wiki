# Linux系统管理_ps_ssh

## ps

- `--help all`, 查看所有帮助

### 基本选项

- `-e`, 查询所有进程

### 限定范围

- `-p, p, --pid {PID1} {PID2}`, 查询指定进程ID
- `-u, U, --user {UID1},{UID2}`, 查询指定effective用户ID或name
- `-U, --User {UID}`, 查询指定real用户ID或name

### 输出格式

- `--headers`, 每页都显示标题
- `--no-headers`, 不显示标题
- `-f`, 输出所有信息，包含UID, PID, PPID, C, STIME, TTY, TIME, CMD
- `-o, o, --format {format}`, 指定输出格式，如：`ps -o pid,args`, `ps -ew -o pid,ppid,user,cmd`
- `u`, 用户友好的格式, 包含USER, PID, %CPU, %MEM
- `-H`, 显示进程层级关系

---

- 查询进程启动路径: `ls -l /proc/{pid}/exe`
- 列出进程调用的文件列表: `lsof -p {pid}`
- 用管道作为输入参数执行命令: `echo /home | xargs ls -l` == `ls -l /home`


## lsof(list open files)

!!! warning "root运行"

### 1. 列出打开文件的进程

```bash
$ lsof /path/to/file
```

### 2. 列出进程打开的文件

```bash
$ lsof -c {process name}
$ lsof -p {pid}
```

### 3. 列出网络连接

```bash
$ lsof -i [tcp|udp]
$ lsof -i [tcp|udp]:port
```

### FD文件描述符

1. cwd：表示current work dirctory，即：应用程序的 **当前工作目录**，这是该应用程序启动的目录，除非它本身对这个目录进行更改
1. rtd：root directory;
1. txt：该类型的文件是程序代码，如应用程序 **二进制文件** 本身或共享库
1. mem：memory-mapped file;
1. 0：表示标准输出
1. 1：表示标准输入
1. 2：表示标准错误

一般在标准输出、标准错误、标准输入后还跟着文件状态模式

1. u：表示该文件被打开并处于读取/写入模式
1. r：表示该文件被打开并处于只读模式
1. w：表示该文件被打开并处于
1. 空格：表示该文件的状态模式为unknow，且没有锁定
1. -：表示该文件的状态模式为unknow，且被锁定

同时在文件状态模式后面，还跟着相关的锁

1. N：for a Solaris NFS lock of unknown type;
2. r：for read lock on part of the file;
3. R：for a read lock on the entire file;
4. w：for a write lock on part of the file;（文件的部分写锁）
5. W：for a write lock on the entire file;（整个文件的写锁）
6. u：for a read and write lock of any length;
7. U：for a lock of unknown type;
8. x：for an SCO OpenServer Xenix lock on part of the file;
9. X：for an SCO OpenServer Xenix lock on the entire file;
10. space：if there is no lock.

### TYPE文件类型

1. DIR：表示目录
1. REG
1. CHR：表示字符类型
1. BLK：块设备类型
1. UNIX：UNIX域套接字
1. FIFO：先进先出 (FIFO) 队列
1. IPv4：网际协议 (IP) 套接字


## 定时任务

- 星号（`*`）：代表所有可能的值，例如month字段如果是星号，则表示在满足其它字段的制约条件后每月都执行该命令操作。
- 逗号（,）：可以用逗号隔开的值指定一个列表范围，例如，“1,2,5,7,8,9”
- 中杠（-）：可以用整数之间的中杠表示一个整数范围，例如“2-6”表示“2,3,4,5,6”
- 正斜线（/）：可以用正斜线指定时间的间隔频率，例如“0-23/2”表示每两小时执行一次。同时正斜线可以和星号一起使用，例如*/10，如果用在minute字段，表示每十分钟执行一次。

### /etc/crontab

```
 .---------------- minute (0 - 59)
 |  .------------- hour (0 - 23)
 |  |  .---------- day of month (1 - 31)
 |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
 |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
 |  |  |  |  |
 *  *  *  *  * user-name command
```

### /var/spool/cron


## 重启服务

```bash
# 方式一
systemctl restart xxx.service
# 方式二
service xxx restart
# 开机启动
systemctl enable xxx
```


## 关机

```bash
shutdown -h now  # 将系统服务停掉后立刻关机
```


## ssh

### Ubuntu安装ssh

```bash
$ sudo apt-get install openssh-server
```

### Ubuntu允许root通过ssh直接登录

```bash
#修改/etc/ssh/sshd_config
PermitRootLogin yes
#重启ssh服务
ssh stop/waiting
ssh start/running, process 27639
```

### 设置ssh连接不超时

#### 修改sshd_config

配置文件路径: `/etc/ssh/sshd_config`

> ClientAliveInterval 300  #服务器向客户端请求消息的时间间隔, 设置成3600秒或更长.
> ClientAliveCountMax 0  #服务器发出请求后客户端没有响应的最大次数, 超过自动断开. 默认客户端不会响应. 设置成3或更大.

重新载入配置文件

```bash
service sshd reload
```

#### 修改TMOUT环境变量

配置文件路径: `/etc/profile`

> export TMOUT=300  #设置为3600或更长.

重新载入配置文件

```bash
source profile
echo $TMOUT  #查看是否生效
```

参考：[https://www.cnblogs.com/enjoycode/p/5022607.html](https://www.cnblogs.com/enjoycode/p/5022607.html)


### 使用ssh公私钥对登录

1. 客户端生成公私钥对`ssh-keygen -t rsa`, 私钥设置口令, 生成路径: `C:\Users\xxx\.ssh\id_rsa, id_rsa.pub`
1. 将公钥上传到服务器
1. 配置sshd_config

    ```
    # 开启证书登录
    RSAAuthentication yes
    PubkeyAuthentication yes
    # 将id_rsa.pub内容拷贝到authorized_keys
    AuthorizedKeysFile %h/.ssh/authorized_keys
    # 禁用密码登录
    PasswordAuthentication no
    ```

1. 重启SSH: `/etc/init.d/ssh restart`
1. 客户端登录: `ssh -i /xxx/.ssh/id_rsa xxx@<ssh_server_ip>`

!!! quote "参考链接: [id_rsa id_pub 公钥与私钥](https://blog.csdn.net/diyxiaoshitou/article/details/52471097)"

#### known_hosts

SSH会把 **访问过** 的计算机的 **公钥** 都记录在`~/.ssh/known_hosts`中, 当下次访问相同的计算机时, OpenSSH会核对公钥, 如果公钥不同, OpenSSH会发出警告, 避免受到DNS Hijack攻击

使用`ssh -i /xxx/.ssh/id_rsa xxx@<ssh_server_ip>`登录时, 如果存在known_hosts且文件中不包含远程机器的IP, 会登录失败

- 解决方法一(临时): 删除known_hosts
- 解决方法二: 在known_hosts中添加远程机器的IP和公钥
- 解决方法三(永久): 在`~/.ssh/config`中添加

    ```
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ```


## sftp

```bash
$ sftp -oPort=22 username@x.x.x.x
username@x.x.x.x's password:
Connected to x.x.x.x.
sftp> ls -al
drwxr-xr-x    3 0        0            4096 Oct 12 04:17 .
drwxr-xr-x    3 0        0            4096 Oct 12 04:17 ..
drwxr-x---    2 1001     1002         4096 Oct 12 06:07 dirs
sftp>
```
