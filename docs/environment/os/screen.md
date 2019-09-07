# screen

Screen官方网站: <http://www.gnu.org/software/screen/>

Screen用于执行长时间 {==不能中断==} 的备份, 测试, 传输任务(恢复会话), 以及 {==共享==} 终端会话窗口

```bash
$ screen -ls
No Sockets found in /run/screen/S-stack.

# 创建并进入screen会话
$ screen -S xxx
# Attached代表活动会话(有人接入)
$ screen -ls
There is a screen on:
        6455.stk        (09/07/2019 03:33:14 AM)        (Attached)
1 Socket in /run/screen/S-stack.

# 退出会话
Ctrl + a, d
[detached from 6455.stk]
$ screen -ls
There is a screen on:
        6455.stk        (09/07/2019 03:33:14 AM)        (Detached)
1 Socket in /run/screen/S-stack.

# 恢复会话
$ screen -x ID
# 或
$ screen -r xxx

# 查看系统登录情况
$ w
 03:51:38 up  4:07,  3 users,  load average: 0.60, 0.62, 0.65
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     tty1     -                12Jul19 56days  0.02s  0.01s -bash
root     pts/1    192.168.1.112    24Aug19  1.00s  0.13s  0.00s screen -r stk
stack    pts/3    :pts/1:S.0       03:50    1.00s  0.03s  0.00s w
```


!!! quote "参考链接: [Linux之screen命令使用技巧](https://blog.51cto.com/4081735/2093492)"
