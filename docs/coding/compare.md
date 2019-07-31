# compare

## shebang

python为脚本语言，会在第一行写shebang，而go没有。

```python
#!/usr/bin/python
```

## main

go必须要有main方法作为程序入口，而python没有。

```go
package main

func main() {
    //...
}
```


## 注释

```python tab="python"
# 单行注释

"""
多行注释
"""

'''
多行注释
'''
```

```go tab="go"
// 注释
```


## 打印输出

```python tab="python"
print("hello world!")
# 输出多个元素
print(a, b, c)
# end关键字，控制单行输出，末尾添加指定字符。
print(x, end=',')
```

```go tab="go"
fmt.Printf("hello, world\n")
// 输出多个元素
fmt.Println(a, b, c, d, e)
// 格式化输出
fmt.Printf("the %d ele is %d\n", i, v)
```


## 运行

```bash tab="python"
python xxx.py
```

```bash tab="go"
go run xxx.go
```


## 数据类型

```python
# 布尔值
isTrue = True
isFalse = False
```

```go
```

 tab="python"

 tab="go"

### 数据类型转换

```python tab="python"
# byte  -->  int
int.from_bytes(xxx, byteorder='big')
# string  -->  int
xxxint = int(xxxstr)
```


## 变量赋值

```python tab="python"
# 自动转换类型
a, b = 0, 1
```

```go tab="go"
// 声明类型
var c, d int [= 1, 2]  //赋值
// 简洁赋值，只能用在函数内部
e := 3
```


## for循环

```python tab="python"
# 对列表进行遍历
names = ['Alice', 'Bob', 'Cavin', 'David']
for name in names:
  # ...
else:
  # ...

# 使用range函数生成一个数字范围列表，左闭右开区间
for i in range(len(names)):
  print(i, names[i])
```

```go tab="go"
// 对数组进行遍历
primes := [6]int{2, 3, 5, 7, 11, 13}
// 直接使用range关键字遍历数组，返回值第一个为下标，第二个为元素副本，可使用_忽略
for i, v := range primes {
    // ...
}

// 循环
for i := 0; i < 5; i++ {
	fmt.Println(i)
}
```


## 函数

```python tab="python"
def xxx(arg1, arg2):
    # TODO:
    return xxx
```

```c tab="c"
int add(int a, int b)
{
    return a + b;
}
```


## 导入包

```python tab="python"
# 0x00_导入文件名
import filename

filename.func()

# 0x01_只导入文件中def定义的方法
from filename import func

func()

# 0x02_包目录下需包含空的__init__.py
import sound.effect
sound.effect.area()
```

```go tab="go"
// project/src下的main.go
package main

// 创建包路径如：math/rand，目录内所有文件都是
package rand

//////

// 导入包
import (
    "math/rand"
)

rand.xxx()
```

```c tab="c"
#include <stdio.h>
#include <stdlib.h>
```


## 类

```python tab="python"
# 定义类
# (object)代表继承自object
class User(object):
    # 定义构造方法
    def __init__(self, nm, pd):
        self.name = nm
        self.password = pd

user = User('alice', 'Admin@123')

# output: alice, Admin@123
print('{user.name}, {user.password}'.format(user=user))
```

## 结构体

```c tab="c"
struct Point
{
    // 属性默认公有
    float x, y;
};
```

## 指针

```c tab="c"
Point* position = NULL;

position->x
position->y
```

## 宏定义

```c tab="c"
#if xxx
#define XXX xxx(xxx)
#else
#define YYY yyy(yyy)
#endif
```


## 库函数

```python tab="Python"
# 时间
import time
# 当前时间(自1970-1-1, 以秒为单位)
print(time.time())  # 1564106732.322287
# 转换为时间元组
# time.struct_time(tm_year=2019, tm_mon=7, tm_mday=26, tm_hour=10, tm_min=20, tm_sec=45, tm_wday=4, tm_yday=207, tm_isdst=0)
print(time.localtime(time.time()))
# 格式化时间
# Fri Jul 26 10:22:56 2019
print(time.asctime(time.localtime(time.time())))

# 自定义格式化
# 2019-07-26 10:29:16
print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
# %a 简化星期, %b 简化月份
# Fri Jul 26 10:29:16 2019
print(time.strftime("%a %b %d %H:%M:%S %Y", time.localtime()))
# 反格式化
timestr = 'Fri Jul 26 10:22:56 2019'
# 1564107776.0
print(time.mktime(time.strptime(timestr, "%a %b %d %H:%M:%S %Y")))

# sleep秒
time.sleep(6)

# 月历
import calendar
#     July 2019
# Mo Tu We Th Fr Sa Su
# 1  2  3  4  5  6  7
# 8  9 10 11 12 13 14
# 15 16 17 18 19 20 21
# 22 23 24 25 26 27 28
# 29 30 31
print(calendar.month(2019, 7))
```


## 规范

### Python

1. 最后空一行
