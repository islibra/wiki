# helloperl

Practical Extraction and Report Language

```perl
#!/usr/bin/perl

print "Hello Perl!\n";
```

!!! warning "特别注意每句后面的分号或逗号!!!"


## 正则表达式

```perl
$str = "this is a global var\n";

if($str =~ /lob/){
    print("match\n");
    print("$`\n");
    print("$&\n");
    print("$'\n");
} else {
    print("not match\n");
}

if($str =~ /th(.*?)lob(.*?)ar/){
    print("$1\n");
    print("$2\n");
}
```

## 文件操作

```perl
# < 只读
# > 写入(清空文件内容)
# +< 读写(头部插入)
# +> 读写(清空文件内容)
# >> 头部追加
# +>> 尾部追加
open(DATA, "<file.txt") or die "file open error, $!";
while(<DATA>){
    print("$_");
}
```

## 包

```perl
#!/usr/bin/perl

$i = 1;
print("package: ", __PACKAGE__, "$i\n");

# 创建包
package Mypkg;

$i = 10;
print("package: ", __PACKAGE__, "$i\n");

# 返回默认包
package main;
print("package: ", __PACKAGE__, "$i\n");
$i = 100;
print("package: ", __PACKAGE__, "$i\n");
# 访问其他包
print("package: ", __PACKAGE__, "$Mypkg::i\n");

# TRUE
1;
```

## 模块

```perl
# filename: Foo.pm
#!/usr/bin/perl

package Foo;

sub bar
{
  print("hello, $_[0]\n");
}

sub blat
{
  print("hi, $_[0]\n");
}

1;


# filename: test.pl
#!/usr/bin/perl
# 运行时引入
require Foo;

Foo::bar("a");

# 编译时引入
# filename: test.pl
#!/usr/bin/perl

use Foo;  # 如果存在::, 相当于路径分隔符

bar("a");
```

### 创建模块

```bash
$ h2xs -AX -n  ModuleName
```

### 安装模块

```bash
$ tar xvfz Person.tar.gz
$ cd Person
$ perl Makefile.PL
$ make
$ make install
```

### 查看已安装模块

```bash
$ instmodsh
l
```

### 打印库路径

```bash
$ perl -e 'print "@INC"'
```

## 库函数

### chomp

- chop, 删除最后一个字符
- chomp, 删除最后的`\n`
