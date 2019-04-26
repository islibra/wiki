# CRC碰撞

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
