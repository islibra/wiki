# C语言安全编程

???+ danger
    带`$-`的可导致程序崩溃

## $-指针, 资源描述符, BOOL变量必须初始化

```c++ tab="正确的做法"
char *msg = NULL;
int fd = -1;
BOOL success = FALSE;
```

```c tab="默认值为NULL"
char *str2;
// str2 is (null)
printf("str2 is %s\n", str2);
```

```c tab="默认随机值"
char *str2;
if(1 == 2) {  // if条件不满足,不会初始化
    str2 = (char *)malloc(5);
}
// str2 is 1▒I▒▒^H▒▒H▒▒▒PTI▒▒@
printf("str2 is %s\n", str2);
if(str2 != NULL) {
    printf("str2 to be free is not initialized.");
    free(str2);
}
// *** Error in `./a.out': free(): invalid pointer: 0x0000000000400600 ***
// ...
// str2 to be free is not initialized.Aborted (core dumped)
```

> 例外: 对于全局变量自动赋值为0.

## 资源句柄释放后立即赋初值

```c++
int fd = -1;
// ...
close(fd);
fd = -1;
```

## 类成员变量必须在构造函数中赋初值

## 调用memset时禁止使用sizeof(指针)

```c hl_lines="9 10 21"
// 声明指针类型
char *str;
// 申请内存
str = (char *)malloc(15);

// sizeof(str) is 8
printf("sizeof(str) is %d\n", sizeof(str));
// Error! 调用memset时禁止sizeof(指针)
memset(str, '$', sizeof(str));
// String is $$$$$$$$
printf("String is %s\n", str);
// 获取指针大小应使用sizeof(char *)
// sizeof(char *) is 8
printf("sizeof(char *) is %d\n", sizeof(char *));

// 数组
char names[5];
// sizeof(names) is 5
printf("sizeof(names) is %d\n", sizeof(names));
memset(names, '$', sizeof(names));
// names is $$$$, 最后一个元素被设置为\0
printf("names is %s\n", names);
```

## $-断言要作为宏定义

```c
#include <assert.h>

// 生产环境下要删掉
#define DEBUG

#ifdef DEBUG
#define ASSERT(f) assert(f)
#else
#define ASSERT(f) ((void)0)
#endif

void myfunc(int i) {
    ASSERT(i == 5);
    printf("success\n");
}

int main()
{
    printf("i == 5\n");
    myfunc(5);
    printf("i == 6\n");
    myfunc(6);
}
```

## 运行时错误严禁使用断言

```c
FILE *fp = fopen(path, "r");
ASSERT(fp != NULL);
char *str = (char \*)malloc(MAX_LINE);
ASSERT(str != NULL);
char *p = strstr(str, "substr");
ASSERT(p != NULL);
int age = atoi(p + 4);
ASSERT(age > 0);
```

## API参数校验严禁使用断言

## 严禁在断言内修改操作

```c
ASSERT(p1 = p2);
ASSERT(i++ > 100);
ASSERT(close(fd) == 0);
```

## 函数参数为指针时, 必须同时指定指针指向内存的大小

```c hl_lines="21 27"
void parseMsg(char *msg, size_t msglen) {
    ASSERT(msg != NULL);
    ASSERT(msglen > 0);

    // 越界读写
    printf("msg[0] is %c, msg[20] is %c\n", msg[0], msg[20]);
    msg[20] = 'a';
    printf("write msg[20] = a, msg[0] is %c, msg[20] is %c\n", msg[0], msg[20]);
}

int main()
{
    char \*str;
    // 申请内存
    size_t len = 15;
    str = (char \*)malloc(len);
    strcpy(str, "islibra");
    // String is islibra, Address is 17400864
    printf("String is %s, Address is %u\n", str, str);

    parseMsg(str, len);

    char names[5];
    memset(names, '$', sizeof(names));
    // names is $$$$
    printf("names is %s\n", names);
    parseMsg(names, sizeof(names));
}
```

> 例外: `const char *msg`

## 函数参数或返回值为指针时, 使用const修饰

## $-死循环

## 有可能失败的操作不能放在构造函数里, 如: new
