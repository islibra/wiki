# C语言安全编程

## 初始化

### $-指针, 资源描述符, BOOL变量必须初始化

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

### 资源句柄, 内存释放后立即赋初值

```c++ hl_lines="4 11"
int fd = -1;
// ...
close(fd);
fd = -1;

double *dp = NULL;
dp = new double;
// ...
// 释放内存
delete dp;
dp = NULL;
```

### 类成员变量必须在构造函数中赋初值

### malloc, new出来的内存使用memset_s清零

### 调用memset时禁止使用sizeof(指针)

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

### 有可能失败的操作不能放在构造函数里, 如: new

## 断言

### $-断言要作为宏定义

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

### 运行时错误严禁使用断言

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

### API参数校验严禁使用断言

### 严禁在断言内修改操作

```c
ASSERT(p1 = p2);
ASSERT(i++ > 100);
ASSERT(close(fd) == 0);
```

## 函数参数

### 函数参数为指针时, 必须同时指定指针指向内存的大小

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

### 函数参数或返回值为指针时, 使用const修饰

## 数组越界

### 字符串操作确保有足够的存储空间

```c hl_lines="11"
// 源字符串
char *str = "helloworld!\n";
printf("%s", str);
// 目的字符串
char dst[20] = {0};
int i = 0;
// 字符串以\0结束, \n换行, sizeof(dst)保证不会数组越界
while(*str != '\0' && *str != '\n' && i<(sizeof(dst)-1)) {
    dst[i++] = *str++;
}
// 保留最后一位存储\0
dst[i] = '\0';
printf("%s\n", dst);
```

> memcpy、memmove、memcpy_s、memmove_s

### 索引来自外部输入, 防止数组越界

```c
char readCharFromArray(const char *str, size_t len) {
    int offset = 3;  // 偏移值来自外部输入
    if(offset >= 0 && offset < len) {
        return str[offset];
    }
    return str[0];
}
char dst[20] = {0};
// ...
char c = readCharFromArray(dst, sizeof(dst));
printf("%c\n", c);
```

### 禁止使用外部输入作为格式化字符串

```c
char *str = "helloworld!\n";
// 如果str来自外部输入, 禁止使用print(str);
printf("%s", str);
```

- 格式化输出函数：xxxprintf
- 格式化输入函数：xxxscanf
- 格式化错误消息函数：err()，verr()，errx()，verrx()，warn()，vwarn()，warnx()，vwarnx()，error()，error_at_line()
- 格式化日志函数：syslog()，vsyslog()

> 格式化参数类型和个数必须与实参一致

## 整数

### $-溢出, 反转, 除0

```c
int i = 0;
// Floating point exception (core dumped)
int j = 5/i;
int k = 5%i;
```

### 运算结果赋值给更大类型之前先转换为更大类型

```c
unsigned int ia = 0x10000000;
unsigned long long lla = ia * 0xab;
// B0000000
printf("%llX\n", lla);
lla = (unsigned long long)ia * 0xab;
// AB0000000
printf("%llX\n", lla);
```

### 禁止对有符号数进行位运算

### 禁止整数与指针相互转化

### $-死循环

## 内存

### 申请内存前对大小校验, 防止为0, 负, 过多申请

!!! info "申请0, 负都不会导致程序崩溃, 但要注意是否引用空指针"
    ```c
    #include <stdio.h>
    #include <stdlib.h>

    // 测试两个无符号数相加赋值给有符号数, 申请内存
    int main() {
        // unsigned int x = 2147483647;
        unsigned int x = 4294967295;
        unsigned int y = 1;
        int z = (int)(x+y);
        // z is -2147483648
        // z is 0
        printf("z is %d\n", z);
        // 负数申请不到内存, 返回NULL
        // 0申请成功
        char *str = (char *)malloc(z);
        if(str != NULL){
            printf("success\n");
        }
        // str is (null)
        // str is
        printf("str is %s\n", str);
        if(str != NULL){
            printf("str is not NULL");
            free(str);
        }
        return 0;
    }
    ```

### 判断内存申请是否成功

## 文件

### 创建文件时指定访问权限

### 文件路径标准化

## 敏感信息

## 随机数

禁用rand(), 推荐`/dev/random`

## 禁用string类保存敏感信息

## 危险函数

### realloc

```c
void *realloc(void *ptr, size_t size);
1. ptr!=NULL, size>0, 重新申请内存
2. ptr==NULL, size>0, malloc(size)
3. size==0, free(ptr)
```

### 命令注入

system、popen、WinExec、ShellExecute、execl, execlp, execle, execv, execvp、CreateProcess

> 建议linux使用exec系列函数, 禁用/bin/sh

dlopen/LoadLibrary

### SQL注入

- 连接MySQL时调用mysql_query(),Execute()时的入参
- 连接SQL Server时调用db-library驱动的dbsqlexec()的入参
- 调用ODBC驱动的SQLprepare()连接数据库时的SQL语句参数
- C++程序调用OTL类库中的otl_stream()，otl_column_desc()时的入参
- C++程序连接Oracle数据库时调用ExecuteWithResSQL()的入参

### 内存操作

- 内存拷贝函数：memcpy(), wmemcpy(), memmove(), wmemmove()
- 内存初始化函数：memset()
- 字符串拷贝函数：strcpy(), wcscpy(),strncpy(), wcsncpy()
- 字符串拼接函数：strcat(), wcscat(),strncat(), wcsncat()
- 字符串格式化输出函数：sprintf(), swprintf(), vsprintf(), vswprintf(), snprintf(), vsnprintf()
- 字符串格式化输入函数：scanf(), wscanf(), vscanf(), vwscanf(), fscanf(),
- fwscanf(),vfscanf(),vfwscanf(),sscanf(), swscanf(), vsscanf(), vswscanf()
- stdin流输入函数：gets()
