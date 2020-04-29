# README

## 李晓龙

三天不读书，智商不如猪。

第一天学到的东西，第二天会忘记50%，第三天忘记80%...

因此，需要一个笔记本，简明扼要的记录下来。这不是一个教程站，只是一个笔记本！


## 链接

### 算法

- [labuladong的算法小抄](https://labuladong.gitbook.io/algo/)
- [力扣题库](https://leetcode-cn.com/problemset/all/)
- python实现的排序算法：<https://github.com/TheAlgorithms/Python>
- python算法动画演示：<https://www.toptal.com/developers/sorting-algorithms/bubble-sort>
- [Github标星2w+，热榜第一，如何用Python实现所有算法](https://mp.weixin.qq.com/s/OHoe6TTX--Ys5G-5yR6juA)
- [Algorithm Visualizer](https://algorithm-visualizer.org/)
- [Algorithm Visualizer - Github](https://github.com/algorithm-visualizer/algorithm-visualizer)
- [python实现基于深度学习的网络欺凌检测模型](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651075726&idx=1&sn=0279918927745ff6a8899ebe27592daa&chksm=bd1fa6058a682f130fb35265924858bbdec766a452c3d742be429a650b8393077524e115ba0b&xtrack=1&scene=0&subscene=92&sessionid=1559655937&clicktime=1559657542&ascene=7&devicetype=android-28&version=2700043b&nettype=3gnet&abtest_cookie=BgABAAgACgALABIAEwAVAAgAnoYeACOXHgBWmR4AxZkeANyZHgD1mR4AA5oeAA2aHgAAAA%3D%3D&lang=zh_CN&pass_ticket=aSykkTizzSN1ZCZ6bSrqfZt5Is9H%2F4Lgw4gEEVKAyiWlMIffXq7CPS6w1pwbAswD&wx_header=1)
- [六维图见过么？Python 画出来了](https://mp.weixin.qq.com/s?__biz=MjM5NzE1MDA0MQ==&mid=2247494113&idx=2&sn=b3c7aa8acb69d5614eb094f5fa3c313d&chksm=a6dcc5d791ab4cc177f18544369e1fbec94061250e1995962b65f0022beb3a21772870426712&xtrack=1&scene=90&subscene=93&sessionid=1561783699&clicktime=1561783780&ascene=56&devicetype=android-28&version=2700043c&nettype=3gnet&abtest_cookie=BgABAAgACgALABIAEwAVAAcAnoYeACOXHgBWmR4AxZkeANyZHgD1mR4ADJoeAAAA&lang=zh_CN&pass_ticket=u4SgrHa3V%2BVQO%2BfgUuR2HEKo4J1p%2Fg5D34vcOrGGVpsdCew73lMP3OAkZ2oLVor5&wx_header=1)


### 云

- CloudMan
    - [《每天5分钟玩转 OpenStack》教程目录](https://mp.weixin.qq.com/s/QtdMkt9giEEnvFTQzO9u7g)
    - [视频 - 在 VirtualBox 中部署 OpenStack](https://mp.weixin.qq.com/s/g-bKZqRFUGXDghIfGJ16_g)
    - 博客园: <https://www.cnblogs.com/CloudMan6/>
- [Docker — 从入门到实践](https://yeasy.gitbooks.io/docker_practice/)
- kubernetes: <https://kubernetes.io/zh/docs/home/>

### 网络安全

- [先知社区](https://xz.aliyun.com/)
- [Golang安全资源合集](https://github.com/re4lity/Hacking-With-Golang/blob/master/README.md)
- 廖新喜：<http://xxlegend.com/>
- [SHODAN](https://www.shodan.io/): 搜索引擎, 搜索internet上的设备.
    - 如搜索使用了`Werkzeug`的服务器, 关键词: `"Server: Werkzeug"`, `"Server: Werkzeug" and "Set=Cookie: session="`
- [NVD - National Vulnerability Database](https://nvd.nist.gov/): NIST - National Institute of Standards and Technology, U.S. Department of Commerce, 包含漏洞搜索和CVSS计算器
- [CVE MITRE - Common Vulnerabilities and Exposures](https://cve.mitre.org/): 漏洞曝光
- [FIRST - Forum of Incident Response and Security Teams](https://www.first.org/cvss/): 全球事件响应和安全论坛, 包含CVSS计算器


### 教程

- Spring Boot: [纯洁的微笑](https://www.cnblogs.com/ityouknow/category/914493.html)
- 肯定会：<https://wistbean.github.io>
- Read the Docs: <https://readthedocs.org/>
- W3Cschool: <https://www.w3cschool.cn/>

### 实用

- [Java 8 API](https://docs.oracle.com/javase/8/docs/api/index.html)
- kindle传书：<https://mp.weixin.qq.com/s/Sag8vLmmLbAs47aIVF3rnQ>

### 大咖

- [sparkdev](https://www.cnblogs.com/sparkdev/)


## 名词解释

- AAA: Authentication, Authorization, Accouting
- CRUD: Create, Retrieve, Update, Delete
- IAM(Identity and Access Management): 认证(身份识别) + 鉴权(访问)
- logo: 商标
- slogan: 口号, 标语
- banner: 旗帜, 标语, 横幅
- MTU: 通道中传输的最大数据单元
- native: 原生的, 如native sql
    - Cloud Native: 在云环境下构建、运行、管理软件，充分利用云基础设施（IaaS）与平台服务（PaaS）。
        - 架构特征：（微）服务化、弹性伸缩、分布式、高可用、多租户、自动化运维。
        - 工程特征：DevOps研发模式、微服务持续交付、自动化工具链。
        - 组织特征：全功能团队、AM架构团队、全栈工程师。

- Underlay: 传统单层网络, 所有转发行为由控制器决定, 通过OpenFlow协议或BGP协议将转发表项下发给转发器
- Overlay: 在Underlay网络上叠加逻辑网络, 转发器不支持OpenFlow或BGP协议, 需要使用隧道技术, 在传统网络上通过路由协议打通各节点, 但是在服务器接入点, 采用隧道技术将数据报文进行封装或解封装

    > 具有独立的控制平面和转发平面

    - 网络Overlay
        - Transparent Interconnection of Lots of Links(TRILL)
        - Network Virtualization using Generic Routing Encapsulation(NVGRE)
        - Stateless Transport Tunneling Protocol(STT)
        - Virtual eXtensible LAN(VxLAN)

    - 主机Overlay
    - 混合Overlay

    !!! quote "参考链接: [数据中心网络里的Underlay和Overlay](https://mp.weixin.qq.com/s?src=3&timestamp=1581759978&ver=1&signature=mFSxihVY3mTo7V4YJDaCGTIL0x7hCNcYJkO8qSuYCXsSSrSSMlYzC21wbq5FDBZ7EvO2wU*ITrx60MI7pX7BxSCpHY2h1fJmeg*mpK9EUepQFtg7mDINnwCQxZLF9IuKi37xcEpGED0i7z9m9zhFG65C6VQuW*l3SZvTBXFbcmo=)"

- proof-of-concept(POC): 对某些想法的一个较短而不完整的实现, 以证明其可行性, 示范其原理
    - 漏洞证明
    - POC测试, 针对客户具体应用的验证性测试, 验证系统方案是否能满足客户需求


## 语录

- 为什么入职拧螺丝而面试要造航母？因为航母上有颗螺丝松了，搬砖的你要快速定位到是哪颗螺丝松了。
- 什么叫垃圾回收的引用计数算法?比如一个团队有一个主管M, 还有A, B, C...等小兵, A的主管是M, 引用计数加1, B的主管是M, 引用计数加1..., 可是这个主管太狠, 每天安排加班, 渐渐的, A离职了, 引用计数减1, B离职了, 引用计数减1, 当减到0的时候, 这个主管就是个垃圾, 需要被回收
- 当前的内容分发不应该是根据用户的喜好或浏览记录去AI，而应该是从海量数据AI出真正有价值的东西推送给用户。我买过马桶你就一直给我推送马桶，那还不赶紧卸载APP？！
- 当前统计局需要给我们的不是人均可支配收入，而是贫富差距，这才是衡量一个领导人干的好不好的标准。
- 虚拟化提高了资源利用率，而云计算对虚拟化进行统一管理。
- 不要奢求项目经理管人的死活，因为他们的KPI里只有进度，除非给他们的KPI增加加班率或项目结束后半年内的离职率。
