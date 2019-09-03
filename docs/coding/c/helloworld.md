# helloworld

```c tab="C"
#include <stdio.h>
#include <stdlib.h>

int main()
{
    printf("Hello World!\n");
    return 0;
}
```

```c++ tab="C++"
#include <iostream>
using namespace std;

int main()
{
    cout << "Hello World!" << endl;
    return 0;
}
```

## 库函数

### strtok_r

字符串分隔

> strtok_r是strtok的可重入版本，也即线程安全版本。剩余字符串存储在静态变量中  -->  使用用户传入的指针重新申请变量

```c tab="函数原型"
#include <string.h>
// str 被分隔字符串, 第一次非空, 连续分隔时为NULL
// delim 分隔符
// saveptr 保存上次分隔剩下的字符串
// return 第一个目标子串
char *strtok(char *str, const char *delim);
char *strtok_r(char *str, const char *delim, char **saveptr);
```

```c tab="代码示例"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
    char str[] = "hello, jason, please come here";
    char *delim = ",";
    char *sptr = NULL;
    char *ptoken = NULL;

    ptoken = strtok_r(str, delim, &sptr);
    printf("Start:\n");
    while(ptoken) {
        printf("ptoken: %s, sptr: %s\n", ptoken, sptr);
        ptoken = strtok_r(NULL, delim, &sptr);
    }
    printf("End!\n");
    return 0;
}
// Start:
// ptoken: hello, sptr:  jason, please come here
// ptoken:  jason, sptr:  please come here
// ptoken:  please come here, sptr:
// End!
```


### ioctl

系统调用, 通过文件操作底层设备输入输出, 如终端

> 这个是用户空间的方法, 在驱动程序中还有ioctl的实现

```c
#include <sys/ioctl.h>

// fd: 文件描述符, request: 控制命令, ...: 可选*argp
// 成功返回0
int ioctl(int fd, unsigned long request, ...);
```
