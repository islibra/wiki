# getting_started

## 题目分类

- Web网络攻防
- RE逆向工程
- Pwn二进制漏洞利用
- Crypto密码攻击
- Mobile移动安全
- Misc安全杂项

## 学习资源

- prompt: <http://prompt.ml/0>，B方向，国外的xss测试。
- RedTigers Hackit: <http://redtiger.labs.overthewire.org/>，B方向，国外sql注入挑战网站，10关，过关的形式，不同的注入，循序渐近地练习。
- We Chall: <http://www.wechall.net/challs>，非常入门的国外ctf题库，很多国内大神都是从这里刷题成长起来的。
- 实验吧：<http://www.shiyanbar.com/courses>，课程。
- i春秋：<https://www.ichunqiu.com/>，线下决赛题目复现，商业培训课程。
- XCTF社区：<http://oj.xctf.org.cn/xctf/>，题库网站，历年题，练习场，比较难，500。
- <https://microcorruption.com/login>，A方向，密码，逆向
- <http://smashthestack.org/>，A方向，简洁，国外，wargames，过关
- idf实验室：<http://ctf.idf.cn/>，基础题目，代理无法访问。
- <http://canyouhack.it/>，国外，入门，有移动安全，代理半访问。
- <http://overthewire.ofg/wargames/>，推荐A方向，国内资料多，老牌wargame，代理无法访问。
- <https://exploit-exercises.com>，A方向，老牌wargame，国内资料多，代理无法访问。
- <http://pawnable.kr/play.php>，pwn类游乐场，不到100题，代理无法访问。
- <http://ctf.moonsoscom/pentest/index.php>，B方向，米安的Web漏洞靶场，基础，核心知识点，代理无法访问。

## 推荐工具

- 010 Editor：<https://www.sweetscape.com/010editor/>，16进制编辑器。
- Binwalk：<https://github.com/ReFirmLabs/binwalk>，分析，逆向，查看图片源格式。
- AZPR:
    - zip密码爆破6位以内
    - 字典
    - aircrack-ng: 使用字典跑握手包密码
    - 掩码
    - 将明文文件压缩成zip，判断CRC32一致，明文攻击

!!! quote "代码"
    [构造字典](../code/%E6%9E%84%E5%BB%BA%E5%AD%97%E5%85%B8/)

- pyc反编译：<https://tool.lu/pyc/>
- <https://github.com/truongkma/ctf-tools>
- <https://github.com/zardus/ctf-tools>
- <https://github.com/TUCTF/Tools>

## 比赛

- CTF TIME: <https://ctftime.org/>，国际比赛，有很多基础的。
- XCTF社区：<https://www.xctf.org.cn/>，国内比赛，比较难。
- DefCon拉斯维加斯举办的年度黑客盛会
- NorthSec蒙特利尔举办的年度安全大会
- NCL国家网络联盟面向高中生和大学生的解题模式CTF

## 解题思路

1. 观察是否16进制，直接放到Burp中`Decode as ASCII hex`。
1. 打开zip包，查看CRC，根据题目提示进行CRC碰撞{>>只适用于压缩文件较小的情况<<}，如：[flag为6位数](../code/CRC%E7%A2%B0%E6%92%9E)。

## 特征

- zip：以PK开头，包含文件路径。
- zip伪加密：标记位。
- 已有zip中文件，明文攻击。
- 使用`binwalk`查看，缺少文件头`Zip archive data...`，缺少文件尾`End of Zip archive...`，使用16进制编辑器添加头尾修复zip。
- jpg：以FF D8开头，FF D9结尾，图片浏览器忽略FF D9以后的内容，后面可隐写。

## 方法

1. 分离图片和zip:
    - linux foremost
    - 直接修改后缀为zip（隐写了多个文件会失败）
2. 解压伪加密zip：
    - MAC或Kali直接打开
    - `java -jar ZipCenOp.jar r xxx.zip`
    - 16进制编辑标记位为`00`


!!! quote "参考文章"
    - [CTF比赛中关于zip的总结](http://3ms.huawei.com/km/groups/2034125/blogs/details/2651133?l=zh-cn&moduleId=)

??? example "待阅读"
    - [【华安解密之DDoS攻防】12 TCP原理篇之SYN-ACK/ACK/FIN/RST Flood](http://3ms.huawei.com/km/blogs/details/2394309)
