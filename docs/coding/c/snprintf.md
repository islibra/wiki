# snprintf

## 函数原型

```c
int snprintf(char *str, size_t size, const char *format, ...)
```

将可变参数按照format格式化为字符串，在拷贝到str中。

## puts

### 函数原型

```c
# include <stdio.h>
int puts(const char *s)
```

将字符串输出到屏幕。

## open

### 函数原型

```c
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
int fd = open(const char *pathname, int flags, mode_t mode)
```

返回文件句柄，一般从3开始。通过close(fd)将句柄返回给系统。

!!! note
    文件句柄：标准输入0，标准输出1，标准错误2

- pathname: 文件路径
- flags:
    - 主类（互斥）
        - O_RDONLY只读
        - O_WRONLY只写
        - O_RDWR读写
    - 副类
        - O_CREAT如果不存在则创建
        - O_EXCL如果使用O_CREAT且文件存在则报错
        - O_NOCTTY
        - O_TRUNC如果文件存在则删除文件内容
        - O_APPEND追加
- mode: 指定新建文件权限如0755
