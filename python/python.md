# 安装

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

# Start

- 解释型语言
- 面向对象
- 用缩进表示代码块
- 复合赋值

示例代码：  
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

## 注释

```python
# 这是单行注释

"""
这是多行注释
"""

'''
这也是多行注释
'''
```

## 数据类型

- 整数
- 长整数
- 浮点数
- 复数
- 字符串：单引号，双引号，三引号指定多行字符串，自然字符串r"this is a line with \n"


参考：<https://www.w3cschool.cn/python3/python3-step1.html>
