# 问题现象

```bash
$ git clone git@xxx.git
Cloning into 'xxx'...
ssh_exchange_identification: Connection closed by remote host
fatal: Could not read from remote repository.

Please make sure you have the correct access rights
and the repository exists.
```

# 问题分析

可能是由于修改了帐号口令导致原公私钥对失效导致。

# 解决方法

重新生成公私钥对：`$ ssh-keygen -t rsa -C xxx@email.com`  
默认生成位置：`C:\Users\xxx\.ssh`  
将`id_rsa.pub`中的内容拷贝到git网站配置中。
