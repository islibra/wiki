解释型，面向对象。  
```
#!/usr/bin/python
print("Hello, World!");
```

# 安装

下载[源码包](https://www.python.org/ftp/python/3.7.2/Python-3.7.2.tgz)，解压，执行  
```
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
```
# /usr/local/bin/python3 -V
Python 3.7.2
```  
Done!
