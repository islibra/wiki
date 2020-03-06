# 0x00_hellopython

## 安装

### Windows

1. 安装Python3
1. 修改`C:\Users\xxx\AppData\Local\Programs\Python\Python37`下的python.exe为python3.exe, 修改`\Scripts`下的pip.exe为pip_bak.exe
1. 将两个路径添加到path
1. 安装Python2
1. 修改`C:\Python27`下的python.exe为python2.exe, 修改`\Scripts`下的pip.exe为pip_bak.exe
1. 将两个路径添加到path
1. 打开cmd, `python2 -V`, `python3 -V`

### Linux

下载[源码包](https://www.python.org/ftp/python/3.7.2/Python-3.7.2.tgz)，解压，执行  
```bash
./configure
make & make install
```

报错：`zipimport.ZipImportError: can't decompress data; zlib not available`  
1. 安装[zlib](https://www.zlib.net/zlib-1.2.11.tar.gz)
1. 修改`Modules/Setup`中的`zlib zlibmodule.c -I$(prefix)/include -L$(exec_prefix)/lib -lz`，去掉前面注释。

报错：`ModuleNotFoundError: No module named '_ctypes'`  
1. 安装[libffi](ftp://sourceware.org/pub/libffi/libffi-3.2.1.tar.gz)
1. `apt-get install --reinstall zlibc zlib1g zlib1g-dev`
1. `apt-get install libffi-dev libssl-dev libreadline-dev -y`

执行：  
```bash
/usr/local/bin/python3 -V
Python 3.7.2
```  
Done!

## 配置pip源

### Windows

在`C:\Users\xxx`创建`pip\pip.ini`

```
[global]
trusted-host=xxx
index-url=xxx
```

### Linux

```bash
$ vim ~/.pip/pip.conf
[global]
trusted-host=mirrors.aliyun.com
index-url = http://mirrors.aliyun.com/pypi/simple/
```


## 反编译

### 方式一

1. [Easy Python Decompiler](https://sourceforge.net/projects/easypythondecompiler/)
1. 统一改名：`find ./ -name "*.pyc_dis" | awk -F "." '{print $2}' | xargs -i -t mv .{}.pyc_dis .{}.py`

### 方式二

1. `pip --proxy=http://l0025xxxx:pass%40word@proxy.xxx.com:8080 install uncompyle6`
1. `uncompyle6 -o . func.pyc`


## Start

- 解释型语言
- 面向对象
- 用缩进表示代码块
- 复合赋值

示例代码：

!!! warning "文件命名不能与库中的类重名"

```python
#!/usr/bin/python3
print("hello world!")
a, b = 0, 1
while b < 10:
  print(b)
  a, b = b, a+b

x, y = 0, 1
while y < 100:
  print(y, end=',')  #end关键字，控制单行输出，末尾添加指定字符。
  x, y = y, x+y
```

执行代码：`python hello.py`

### 注释

```python
# 这是单行注释

"""
这是多行注释
"""

'''
这也是多行注释
'''
```

### 数据类型

- Numbers: int, float, bool, complex，使用内置函数type()查询变量指向的 **对象类型**，如：  
```python
a, b, c, d = 2, 5.5, True, 1+2j
print(type(a), type(b), type(c), type(d))

# 数值运算
2/4  #结果浮点数
2//4  #结果向下取整
2*3  #乘法
2**3  #乘方
5+4.2  #混合计算时，总是转换成浮点数
```
- String: 字符串：单引号，双引号，三引号指定多行字符串，自然字符串r"this is a line with \n"
- List
- Tuple
- Set
- Dictionaries


参考：<https://www.w3cschool.cn/python3/python3-data-type.html>
