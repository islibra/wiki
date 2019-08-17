# sec_codes

## md5

```python
import hashlib
from multiprocessing.dummy import Pool as ThreadPool

# MD5截断数值已知 求原始数据
# 例子 substr(md5(captcha), 0, 6)=60b7ef

def md5(s):  # 计算MD5字符串
    return hashlib.md5(str(s).encode('utf-8')).hexdigest()


keymd5 = '078a4'   #已知的md5截断值
md5start = 0   # 设置题目已知的截断位置
md5length = 5

def findmd5(sss):    # 输入范围 里面会进行md5测试
    key = sss.split(':')
    start = int(key[0])   # 开始位置
    end = int(key[1])    # 结束位置
    result = 0
    for i in range(start, end):
        # print(md5(i)[md5start:md5length])
        if md5(i)[0:5] == keymd5:            # 拿到加密字符串
            result = i
            print(result)    # 打印
            break


list=[]  # 参数列表
for i in range(10):   # 多线程的数字列表 开始与结尾
    list.append(str(10000000*i) + ':' + str(10000000*(i+1)))
pool = ThreadPool()    # 多线程任务
pool.map(findmd5, list) # 函数 与参数列表
pool.close()
pool.join()
```


## CRC碰撞

```python
#!/usr/local/bin/python

import binascii, sys

crc = 0x9c4d9a5d

for i in range(100000, 999999 + 1):  # 6位数字
  if binascii.crc32(bytes(str(i), encoding="utf8")) == crc:  # 将int转换成string再转换成bytes
    print(i)
    sys.exit()

# str to bytes: bytes(str, encoding="utf8") or str.encode(s)
# bytes to str: str(bytes, encoding="utf8") or bytes.decode(b)
```


## 构建字典

```python
import string

s = string.digits + string.ascii_uppercase  # 数字和大写字母的列表
# 构建4位字典
f = open('dict.txt', 'w')
for i in s:
  for j in s:
    for p in s:
      for q in s:
        f.write(i + j + p + q + '\n')
f.close()
```
