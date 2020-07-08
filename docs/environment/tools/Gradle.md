# [Gradle](https://gradle.org/)

## I. 安装

```sh
# 检查 Java 版本
$ java -version
# 下载安装包
$ curl -k -LO https://services.gradle.org/distributions/gradle-5.6.2-bin.zip
$ unzip gradle-5.6.2-bin.zip
# 设置环境变量
$ export GRADLE_HOME=/home/islibra/gradle-5.6.2
$ export PATH=$GRADLE_HOME/bin:$PATH
# 缓存 jar 包的路径
$ export GRADLE_USER_HOME=$GRADLE_HOME/.gradle
$ gradle -v
```

!!! quote "参考链接"
    - 下载: <https://gradle.org/releases/>
    - 安装: <https://gradle.org/install/>
    - Gradle 使用指南: <https://wiki.jikexueyuan.com/project/gradle/>

## I. FAQ

1. Process 'Gradle Worker Daemon 1' finished with non-zero exit value 137
    - 问题原因: OutOfMemmoryError, Gradle 构建过程中内存耗尽, 导致 worker 进程退出
    - 解决方案: 增大内存
