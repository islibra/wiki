# 读写json

import json模块

- dumps，数据类型转换成字符串
- dump，数据类型转换成字符串并存储在文件中
- loads，字符串转换成数据类型
- load，把文件打开从字符串转换成数据类型

```python
import json

service = {"services":{"name":"nginx","owner":"xxx"}}
print(service)
print(type(service))

service_json = json.dumps(service)
print(service_json)
print(type(service_json))

new_service = json.loads(service_json)
print(new_service)
print(type(new_service))

# 写入文件
with open("/tmp/status.json","w") as wf:
  json.dump(new_service, wf)
  print("write done.")

# 读取文件
with open("/tmp/status.json","r") as rf:
  dic = json.load(rf)
  print(dic)

###
{'services': {'name': 'nginx', 'owner': 'xxx'}}
<class 'dict'>
{"services": {"name": "nginx", "owner": "xxx"}}
<class 'str'>
{'services': {'name': 'nginx', 'owner': 'xxx'}}
<class 'dict'>
{'services': {'name': 'nginx', 'owner': 'aaa'}}
```


```json
{
    "services": {
        "name": "nginx",
        "owner": "aaa"
    }
}
```
