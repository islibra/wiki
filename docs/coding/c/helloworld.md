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

```c
#include <sys/ioctl.h>

// fd: 文件描述符, request: 编码后的请求参数, ...: 未指定类型的指针
// 成功返回0
int ioctl(int fd, unsigned long request, ...);
```
