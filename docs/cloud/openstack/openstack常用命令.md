# openstack常用命令

## 查看版本

```bash
$ cat /etc/*version
```

## 查看资源

- CPU: `lscpu`, `Numactl -H`
- 内存: `virsh capabilities`
- 资源隔离: `cat /opt/fusionplatform/data/cps_config/res_info.json`
    - `cps hostcfg-add --type resgrp-define xxx`
    - `cps hostcfg-item-update ...`
    - `cps commit`
    - `cps hostcfg-show --type resgrp-define xxx`
- 大页内存: `cat /proc/meminfo | grep Huge`
    - `cps hostcfg-add --type kernel xxx`
    - `cps hostcfg-item-update ...`
    - `cps commit`

### 资源组

- `cps resgroup-add --name xxx`
- `cps resgroup-template-add ...`
- `cps hostcfg-item-add ... --type resgrp-define xxx`

### 集群

- `cps cluster-add --host xxx --name xxx`

## 服务

- 查看服务部署节点: `cps template-instance-list --service nova nova-api`
- 重启服务:
    - `cps host-template-instance-operate --service nova nova-api --action stop`
    - `cps host-template-instance-operate --service nova nova-api --action start`
- 指定主机重启服务
    - `cps host-template-instance-operate --service nova nova-api --action stop --host host_id`
    - `cps host-template-instance-operate --service nova nova-api --action start --host host_id`
- 查看服务配置项: `cps template-params-show --service nova nova-api`
- 更改服务配置项:
    - `cps template-params-update --service nova nova-api --parameter key=value`
    - `cps commit`


## 命令行


!!! quote "[Command-Line Tools](https://docs.openstack.org/operations-guide/ops-lay-of-the-land.html#command-line-tools)"
