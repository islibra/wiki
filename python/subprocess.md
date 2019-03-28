# 参数列表

```python
import sys

print(sys.argv[0])  # 代码文件本身
print(sys.argv[1])  # 第一个参数
```

执行结果：  
```bash
python stepone.py test
stepone.py
test
```

# 子进程

subprocess，类似于shell，执行外部命令和程序。

- subprocess.call()，父进程等待子进程完成，返回退出信息。
- subprocess.check_call()，父进程等待子进程完成，返回0，如果returncode不为0，抛出错误`subprocess.CalledProcessError`，对象包含returncode属性，可用`try...except...`检查。
- subprocess.check_output()，父进程等待子进程完成，返回子进程向标准输出的输出结果，如果returncode不为0，抛出错误`subprocess.CalledProcessError`，对象包含returncode和output属性，可用`try...except...`检查。

```python
import subprocess

rs = subprocess.call(['ls', '-l'])
print(rs)
```

执行结果：  
```bash
python subp.py
total 8
-rw-r--r-- 1 root root 70 Mar 28 17:05 stepone.py
-rw-r--r-- 1 root root 83 Mar 28 17:19 subp.py
0
```

## 起一个shell运行

```python
import subprocess

rs = subprocess.call('ls -l', shell=True)
print(rs)
```

执行结果：  
```bash
python subp.py
total 8
-rw-r--r-- 1 root root 70 Mar 28 17:05 stepone.py
-rw-r--r-- 1 root root 90 Mar 28 17:23 subp.py
0
```

## 底层调用

返回子进程，主程序不会自动等待子进程完成，必须调用wait()。

```python
import subprocess

child = subprocess.Popen(['ping','-c','5','www.huawei.com'])
print("parent process")
```

执行结果：  
```bash
python subp.py
parent process
root@SZX1000451827:/home/islibra/python# PING www.huawei.com (10.3.42.32) 56(84) bytes of data.
64 bytes from 10.3.42.32: icmp_seq=1 ttl=250 time=2.70 ms
64 bytes from 10.3.42.32: icmp_seq=2 ttl=250 time=2.66 ms
64 bytes from 10.3.42.32: icmp_seq=3 ttl=250 time=2.66 ms
64 bytes from 10.3.42.32: icmp_seq=4 ttl=250 time=2.55 ms
64 bytes from 10.3.42.32: icmp_seq=5 ttl=250 time=2.58 ms

--- www.huawei.com ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4006ms
rtt min/avg/max/mdev = 2.553/2.633/2.704/0.080 ms
```

```python
import subprocess

child = subprocess.Popen(['ping','-c','5','www.huawei.com'])
child.wait()
print("parent process")
```

执行结果：  
```bash
python subp.py
PING www.huawei.com (10.3.42.32) 56(84) bytes of data.
64 bytes from 10.3.42.32: icmp_seq=1 ttl=250 time=2.86 ms
64 bytes from 10.3.42.32: icmp_seq=2 ttl=250 time=2.59 ms
64 bytes from 10.3.42.32: icmp_seq=3 ttl=250 time=2.81 ms
64 bytes from 10.3.42.32: icmp_seq=4 ttl=250 time=2.96 ms
64 bytes from 10.3.42.32: icmp_seq=5 ttl=250 time=2.89 ms

--- www.huawei.com ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4005ms
rtt min/avg/max/mdev = 2.594/2.823/2.960/0.133 ms
parent process
```

- child.poll()  # 检查子进程状态
- child.kill()  # 终止子进程
- child.send_signal()  # 向子进程发送信号
- child.terminate()  # 终止子进程
- child.pid  # 子进程ID

## 控制输入输出流

```python
import subprocess

child1 = subprocess.Popen(['ls','-l'], stdout=subprocess.PIPE)
child2 = subprocess.Popen(['grep','sub'], stdin=child1.stdout, stdout=subprocess.PIPE)
out = child2.communicate()
print(out)
```

执行结果：  
```bash
python subp.py
(b'-rw-r--r-- 1 root root 226 Mar 28 18:58 subp.py\n', None)
```

communicate为阻塞式，可通过communicate为子进程作为输入：  
```python
import subprocess

child = subprocess.Popen(['wc'], stdin=subprocess.PIPE)
child.communicate("home islibra python".encode())
```

执行结果：  
```bash
python subp.py
      0       3      19
```
