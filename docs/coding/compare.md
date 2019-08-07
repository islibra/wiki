# compare

## 运行环境

```bash tab="C"
# 确认已安装GNU的C编译器
$ gcc -v
```

```bash tab="C++"
# 确认已安装GNU的C++编译器
$ g++ -v
```

## shebang

python为脚本语言，会在第一行写shebang，而go没有。

```python
#!/usr/bin/python
```

## namespace

```c++ tab="C++"
using namespace std;
```

## main

go必须要有main方法作为程序入口，而python没有。

```go tab="go"
package main

func main() {
    //...
}
```

```c tab="C/C++"
int main()
{
    // ...
    return 0;
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

```c tab="C/C++"
// 单行注释
/*
多行注释
*/
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

```c tab="C"
printf("Hello World!\n");
```

```c++ tab="C++"
cout << "Hello World!" << endl;
```

## 运行

```bash tab="python"
python xxx.py
```

```bash tab="go"
go run xxx.go
```

```bash tab="C"
$ gcc helloc.c
$ ./a.out
Hello World!
```

```bash tab="C++"
$ g++ helloworld.cpp
$ ./a.out
Hello World!
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

```c tab="C"
// 只在Windows平台有效
//itoa(a, str, 10);  // 整型, 字符串, 进制
char astr[20] = {0};
sprintf(astr, "%d", a);
printf("a %d to astr is %s\n", a, astr);
```

## 常量

```c tab="C" hl_lines="10 17 20"
// 方法一:
#define HELLOWORLD "Hello World!\n"

// 方法二:
const LEN = 5;

int a = 1;
int b = 2;
// 声明指针为const
const int *pa = &a;
printf("a is %d\n", *pa);
// 修改a的值
a = 3;
printf("a is %d\n", *pa);
// 无法修改指针指向的a的值
// error: assignment of read-only location ‘*pa’
*pa = 4;
printf("a is %d\n", *pa);
// 可以修改指针指向的地址
pa = &b;
printf("b is %d\n", *pa);
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

## 数组

```c tab="C"
// 声明数组并初始化
// 数组长度必须是常量
int ages[3] = {1, 2, 3};
printf("ages[0] is %d\n", ages[0]);
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

```c tab="C"
#include <stdio.h>
#include <stdlib.h>
```

```c++ tab="C++"
#include <iostream>
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

```c++ tab="C++"
#include <iostream>
using namespace std;

class Printer {
public:
    // 构造函数声明
    Printer();
    // 析构函数声明
    ~Printer();

    void displayMsg() {
        cout << "Welcome! size is " << size << endl;
    }

private:
    int size;
    char *msg;
};  // 注意最后的分号

// 构造函数定义
Printer::Printer() {
    size = 0;
    msg = NULL;
}

// 析构函数定义
Printer::~Printer() {
}

int main()
{
    Printer p;
    p.displayMsg();

    return 0;
}
```

## 结构体

```c tab="C"
// 定义结构体
struct Point
{
    // 属性默认公有
    float x, y;
};

// 结构体作为参数
void testStruct(struct Point p) {
    printf("p is %f, %f\n", p.x, p.y);
}

int main()
{
    // 声明结构体
    struct Point p = {1.1, 2.2};
    testStruct(p);
}
```

## 指针 & 动态内存

```c tab="C"
Point* position = NULL;

position->x
position->y

//////

#include <stdio.h>
#include <stdlib.h>

int main()
{
    printf("Hello World!\n");

    // 声明指针类型
    char *str;
    // 申请内存
    str = (char *)malloc(15);
    strcpy(str, "islibra");
    // String is islibra, Address is 17400864
    printf("String is %s, Address is %u\n", str, str);

    // 重新申请内存
    str = (char *)realloc(str, 25);
    strcat(str, " is good!");
    // String is islibra is good!, Address is 17400864
    printf("String is %s, Address is %u\n", str, str);

    // 释放内存
    if(str != NULL) {
        free(str);
    }

    return 0;
}
```

```c++ tab="C++"
// 声明指针并初始化为NULL
double *dp = NULL;
// 申请动态内存
dp = new double;
// 赋值
*dp = 1.23;
cout << "dp is " << *dp << endl;
// 释放内存
delete dp;
dp = NULL;

// 指针指向字符数组
char *pstr = NULL;
pstr = new char[20];
pstr[0] = 'a';
cout << pstr << endl;
delete [] pstr;
pstr = NULL;

// 指针指向指针数组
int ROW = 2;
int COL = 3;
int **ppint = new int* [ROW];
for(int i=0; i<ROW; i++) {
    ppint[i] = new int[COL];
    for(int j=0; j<COL; j++) {
        ppint[i][j] = j;
    }
}
cout << "ppint[1][2] is " << ppint[1][2] << endl;
for(int i=0; i<ROW; i++) {
    delete [] ppint[i];
    ppint[i] = NULL;
}
delete [] ppint;
ppint = NULL;
```

## 宏定义

```c tab="C"
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

```c tab="C"
// 断言
#include <assert.h>

void myfunc(int i) {
    assert(i == 5);
    printf("success\n");
}

int main()
{
    printf("i == 5\n");
    myfunc(5);
    printf("i == 6\n");
    // a.out: helloc.c:8: myfunc: Assertion `i == 5' failed.
    // Aborted (core dumped)
    myfunc(6);
}
```

## 规范

### Python

1. 最后空一行

### JavaScript

1. 语句和`function(){};`后面带分号
