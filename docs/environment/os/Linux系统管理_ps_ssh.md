# Linux系统管理_ps_ssh

## ps

### 选项

- `--help all`, 查看所有帮助
- `--no-headers`, 不显示标题
- `-e`, 查询所有进程
- `-f`, 输出所有信息，包含UID, PID, PPID, C, STIME, 命令行CMD
- `-o {format}`, 指定输出格式，如：`ps -o pid,args`, `ps -ew -o pid,ppid,user,cmd`
- `-w`, 不限制输出宽度
- -p {PID1} {PID2}, 查询指定进程ID
- -u {UID1},{UID2} 查询指定用户


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
