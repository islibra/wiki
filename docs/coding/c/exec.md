# exec

创建新的进程或fork一个新的子进程后，通过exec系统调用将新产生的进程替换为新的进程映像。

包含头文件：`<unistd.h>`

- execl(path, arg), path要启动的程序路径和名称，arg启动程序所带的参数，第一个为命令名，不带路径，以NULL结束。
- execlp(file, arg)
- execle(path, arg, envp[])
- execv(path, argv[]), 命令以数组形式给出且最后一个元素必须是NULL。
- execvp(file, argv[])

```c tab="l"
//可变参数要以一个空指针结束
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    printf("entering main process---\n");
    execl("/bin/ls","ls","-l",NULL);  //利用execl将当前进程main替换掉，所有最后那条打印语句不会输出
    printf("exiting main process ----\n");
    return 0;
}
```

```c tab="p"
//path不用输入完整路径，给出命令名即可，在环境变量中查找
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void)
{
    printf("entering main process---\n");
    if(execlp("ls","ls","-l",NULL)<0)
      perror("excl error");
    return 0;
}
```

!!! quote "参考链接"
    <https://www.cnblogs.com/leijiangtao/p/4483009.html>
