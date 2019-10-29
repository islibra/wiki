# helloperl

Practical Extraction and Report Language

```perl
#!/usr/bin/perl

print "Hello Perl!\n";
```

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
