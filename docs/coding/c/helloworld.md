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

### ioctl

系统调用, 通过文件操作底层设备输入输出, 如终端

> 这个是用户空间的方法, 在驱动程序中还有ioctl的实现

```c
#include <sys/ioctl.h>

// fd: 文件描述符, request: 控制命令, ...: 可选*argp
// 成功返回0
int ioctl(int fd, unsigned long request, ...);
```
