# Linux用户管理

## 配置文件

### 用户/etc/passwd

共7个字段，以冒号分隔。

```
用户名:口令:用户标识号:组标识号:注释性描述:主目录:登录Shell
```

!!! note
    - 用户标识号：是一个整数，系统内部用它来标识用户。一般情况下它与用户名是一一对应的。如果几个用户名对应的用户标识号是一样的，系统内部将把它们视为同一个用户，但是它们可以有不同的口令、不同的主目录以及不同的登录Shell等。通常用户标识号的取值范围是`0～65535`。0是超级用户root的标识号，1～99由系统保留，作为管理账号，普通用户的标识号从100开始。在Linux系统中，这个界限是500。

### 用户组/etc/group

## 用户操作

### 0x00_增加用户

```bash
useradd xxx  # 添加用户xxx
```

???+ note "选项"
    - `-r`, 创建一个系统帐号
    - `-u, --uid UID`, 指定新帐号的UID
    - `-g, --gid GROUP`, 指定新帐号所属的用户组名称或ID
    - `-m`, 创建用户主目录
    - `-s, --shell SHELL`, 指定新帐号登录使用的shell

### 0x01_修改用户

#### 修改密码

```bash
passwd w3cschool  # 设置w3cschool用户的密码
Enter new UNIX password:  # 输入新密码，输入的密码无回显
Retype new UNIX password:  # 确认密码
passwd: password updated successfully
```

#### 修改用户所属组

```bash
usermod -g usergroup username
```

#### 修改用户描述信息

```bash
usermod -c {description} xxx
```

### 0x02_切换用户

```bash
whoami  # 显示当前用户
pwd  # 显示当前目录
su - root  # 切换到root用户
```

#### 更改个人资讯

```bash
chfn
Changing finger information for root.
Name [root]: hnlinux
Office []: hn
Office Phone []: 888888
Home Phone []: 9999999
Finger information changed.
```
