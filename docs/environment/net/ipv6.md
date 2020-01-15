# ipv6

维度 | IPv4 | IPv6
--- | --- | ---
地址 | 4字节，255.255.255.255，每字节8bit，最大255，共32位，总数2^32^=4,294,967,296 | 16字节，ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff，共128位，==双冒号::用于指定任意数目的0==

## 地址

### 单播

- 未指定地址: `::/128`

- 环回地址: `::1/128`

- Link Local Address(LLA): `FE80::/10`

    > 链路本地地址: 报文只在一个LAN内转发

- Globally Unique Addresses(GUA): `2000::/3`

    > 全球唯一单播地址: 公网IP

- Unique Local IPv6 Addresses(ULA): `FC00::/7`

    > 唯一本地地址: 私网IP

### 组播

- 分配的地址: `FF00::/8`
- 被请求节点组播地址: `FF02::1:FF00:0000/104`

### 任播

## 报文格式

- Version
- {--IHL--}
- {~~ToS~>Traffic Class~~}
- {~~Total Len~>Payload Length~~}
- {++Flow Label++}
- {--Identification--}
- {--Flags--}
- {--Fragment Offset--}
- {~~TTL~>Next Header~~}
- {~~Protocol~>Hop Limit~~}
- {--Head Checksum--}
- Source address
- Destination address
- {--Options--}
- {--padding--}

## 新特性

- ARP --> NDP
- Stateless Address Auto Configuration(SLAAC): 无状态地址分配, 基于EUI64规范, 根据MAC自动为LAN内终端分配IP地址

    > 中间插入FFFE, 第7bit取反

- 终端采用临时IPv6地址实现互联网匿名访问
