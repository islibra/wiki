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

```bash tab="Java"
$ java -version
java version "1.8.0_171"
Java(TM) SE Runtime Environment (build 1.8.0_171-b11)
Java HotSpot(TM) 64-Bit Server VM (build 25.171-b11, mixed mode)
```


## shebang

python为脚本语言，会在第一行写shebang，而go没有。

```python tab="Python"
#!/usr/bin/python
```

```perl tab="Perl"
#!/usr/bin/perl
```

## namespace

```c++ tab="C++"
using namespace std;
```

## main

> go必须要有main方法作为程序入口，而python没有。

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

```java tab="Java"
// Demo.java, 文件名必须与类名一致, 首字母大写
public class Demo {

    public static void main(String[] args) {
        // ...
    }

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

```java tab="Java"
// 注释
```

```perl tab="Perl"
# 单行注释

=pod
多行注释
=cut
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

```java tab="Java"
System.out.println("Hello Java!");
```

```perl tab="Perl"
print "Hello Perl!\n";
print("Hello Perl!\n");
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

```bash tab="Java"
# 单个类编译运行
$ javac Demo.java
$ ll
total 32
drwxr-xr-x 2 root root  4096 Aug 31 14:42 ./
drwxr-xr-x 4 root root  4096 Aug 31 11:15 ../
-rw-r--r-- 1 root root   411 Aug 31 14:42 Demo.class
-rw-r--r-- 1 root root   306 Aug 31 14:42 Demo.java
$ java Demo
Hello Java!
```

!!! quote "带package或依赖参见[编译运行](../java/0x01_编译运行/)"


## 数据类型

### python

```python tab="python"
# 布尔值
isTrue = True
isFalse = False
```

### C

```c tab="C"
// 无符号整数类型，它是 sizeof 关键字的结果。
#include <stdlib.h>
size_t
```

??? abstract "整型"
    类型 | 存储大小 | 值范围
    --- | --- | ---
    char | 1 byte | -128 到 127 或 0 到 255
    unsigned char | 1 byte | 0 到 255
    signed char | 1 byte | -128 到 127
    int | 2 或 4 bytes | -32,768 到 32,767 或 -2,147,483,648 到 2,147,483,647
    unsigned int | 2 或 4 bytes | 0 到 65,535 或 0 到 4,294,967,295
    short | 2 bytes | -32,768 到 32,767
    unsigned short | 2 bytes | 0 到 65,535
    long | 4 bytes | -2,147,483,648 到 2,147,483,647
    unsigned long | 4 bytes | 0 到 4,294,967,295

### C++

```c++ tab="C++"
// 字符串

// 形式一: 字符数组, 末尾带\0
char greeting[] = "welcome";
cout << greeting << endl;
char str1[10];
strcpy(str1, greeting);
cout << str1 << endl;

// 形式二: 字符串
#include <string>
string s1 = "hello";
string s2 = "world";
string s3;
int len;
s3 = s1;
cout << s3 << endl;
s3 = s1 + s2;
cout << s3 << endl;
len = s3.size();
cout << len << endl;
```

### php

```php tab="php"
// 被认为是FALSE的布尔值, 其他都被认为是TRUE
1. 整型0, 浮点型0.0
2. 空字符串或字符串"0"
3. 不包含任何元素的数组
4. NULL, 尚未赋值的变量
5. 从空标记生成的SimpleXML对象
```

### 数据类型转换

```python tab="python"
# byte  -->  int
int.from_bytes(xxx, byteorder='big')
# string  -->  int
xxxint = int(xxxstr)
```

```c tab="C"
// 整型转字符串
//itoa(i, str, 10);  // 只在Windows平台有效, 整型, 字符串, 进制
char str[20] = {0};
sprintf(str, "%d", i);
printf("i %d to str is %s\n", i, str);

// 字符串转整型
#include <stdlib.h>
char *str2 = "thisisastring";
int i = atoi(str2);
// str2 is thisisastring, i is 0
printf("str2 is %s, i is %d\n", str2, i);
char *str3 = "123456789";
int j = atoi(str3);
// str3 is 123456789, j is 123456789
printf("str3 is %s, j is %d\n", str3, j);
```

```c++ tab="C++"
// string  -->  const char *
cout << s3.c_str() << endl;
// 如果想赋值给另一个char *, 必须使用strcpy
char *ps3 = new char[s3.size() + 1];
strcpy(ps3, s3.c_str());
cout << ps3 << endl;
```

```php tab="php"
// 字符串转换为数值, 包含. e E转换为float, 否则转换为integer, 其他字母忽略.
<?php
$foo = 1 + "10.5";                // $foo is float (11.5)
$foo = 1 + "-1.3e3";              // $foo is float (-1299)
$foo = 1 + "bob-1.3e3";           // $foo is integer (1)
$foo = 1 + "bob3";                // $foo is integer (1)
$foo = 1 + "10 Small Pigs";       // $foo is integer (11)
$foo = 4 + "10.2 Little Piggies"; // $foo is float (14.2)
$foo = "10.0 pigs " + 1;          // $foo is float (11)
$foo = "10.0 pigs " + 1.0;        // $foo is float (11)     
?>
```

```java tab="Java"
// char -> int
int i = Character.getNumericValue(c);
// int -> String
String s = String.valueOf(i);
// 字符串转字符数组
char[] cArray = s.toCharArray();
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

```php tab="php"
<?php
$name = 'Bob';
$company = 'Apple';
echo "$name, $company";  // 输出 "Bob, Apple"
?>
```

```perl tab="Perl" hl_lines="28"
# 使用 use strict; 让所有变量需要强制声明类型。
$a = 10;
print("a is $a\n");

# 列表/数组
@arr = (1, 2, 3);
print("arr is @arr\n");

# Map/Hash
%h = ('a', 1, 'b', 2);
print("h.a is $h{'a'}, h.b is $h{'b'}\n");

# 默认所有变量都是全局变量, 使用my声明私有变量, 使用local临时改变全局变量值
sub hellosub{
    my $str = "i am a private var\n";
    print($str);
    local $str2 = "i am temp changed\n";
    print($str2);
}

$str = "this is a global var\n";
$str2 = "this is another\n";

hellosub();
print($str);
print($str2);

# 特殊变量

# $0: 正在执行的脚本文件名

# $_: 默认输入和模式匹配内容
foreach ('a', 'b', 'c') {
  print("$_\n");
}

# $@: 命令eval的错误消息, 如果为空, 则表示上一次eval命令执行成功

# $ARGV: 从默认的文件句柄中读取时的当前文件名

# @ARGV: 传给脚本的命令行参数列表
# perl xxx.pl arg1 arg2
print("@ARGV\n");
arg1 arg2
```


## C 存储类

> 修饰在变量类型之前

- auto, 局部变量默认
- register, 存储在寄存器而非RAM中的局部变量, 最大等于寄存器大小, 且无法取地址`&`, 通常用于快速访问, 如计数器
- static
    - 局部变量, 在每次函数被调用时保持其值
    - 全局变量, 将作用于限制在声明它的文件内
    - 类成员, 所有对象共享该成员
- extern, 声明该全局变量或函数在其他文件中定义


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
 | fmt.Println(i)
}
```

```perl tab="Perl"
#!/user/bin/perl

# 遍历列表
@list = (1, 2, 3);
# 1.
print $_."\n" for @list;
# 2.
foreach $ele (@list) {
  print("$ele\n");
}

# 遍历Hash
%data = ('hello'=>1, 'perl'=>2, 'world'=>3);
# 1.
while(my ($key,$value) = each(%data)) {
  print("$key $value\n");
}
# 2.
print "$_ $data{$_}\n" for keys %data;
print "$_\n" for values %data;
# 3.
print "$_ $data{$_}\n" foreach keys %data;
```


## 函数

```python tab="python"
def xxx(arg1, arg2):
    # TODO:
    return xxx
```

```c tab="C" hl_lines="10"
// 函数声明
int add(int a, int b);

// 函数定义
int add(int a, int b)
{
    return a + b;
}

// C语言可以通过指针定义输入输出参数
int testParam(int *input, int *output) {
    *output = *input + 1;
    return 0;
}

int main() {
    int i = 0;
    int j = 0;
    testParam(&i, &j);
    // i is 0, j is 1
    printf("i is %d, j is %d\n", i, j);
}
```

```perl tab="Perl"
hellosub("hello", "subperl");

sub hellosub{
    # @_ 表示入参列表
    print("arg 1 is @_[0], 2 is @_[1]\n");
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

### C 头文件

> 包含常量, 宏定义, 全局变量, 函数原型声明, 引用头文件相当于复制头文件的内容

- 编译器自带的头文件: `#include <file>`, 在系统目录的标准列表中搜索
- 程序编写的头文件: `#include "file"`, 在当前目录中搜索

> 放在条件编译中防止被重复引用:

```c
#ifndef HEADER_FILE
#define HEADER_FILE

// ...

#endif
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

```perl tab="Perl"
# filename: Person.pm
package Person;

# 构造函数, 名称可自定义
sub new
{
  my $class = shift;
  my $self = {
    _firstName => shift,  # 注意这里是逗号
    _lastName => shift,
    _ssn => shift,
  };

  print("firstName is $self->{_firstName}\n");
  print("lastName is $self->{_lastName}\n");
  print("ssn is $self->{_ssn}\n");
  # 构造对象
  bless $self, $class;
  return $self;
}

# 返回值
1;


# filename: helloperl.pl
#!/usr/bin/perl

use Person;

$object = new Person("Jack", "John", 123);
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

```c++ tab="C++"
// 字符串拷贝
#include <cstring>
char greeting[] = "welcome";
cout << greeting << endl;
char str1[10];
strcpy(str1, greeting);
cout << str1 << endl;
```

```java tab="Java"
// 求平方
int result = Math.pow(i, 2);
```

## 规范

### Python

1. 最后空一行

### JavaScript

1. 语句和`function(){};`后面带分号

### C/C++

1. 类/结构体定义右花括号后面带分号

    ```c++
    class Xxx {
    };
    struct Xxx {
    };
    ```
