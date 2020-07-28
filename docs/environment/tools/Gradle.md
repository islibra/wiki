# Gradle

!!! quote "Gradle Build Tool: <https://gradle.org/>"

![](https://img.shields.io/badge/Language-Groovy-brightgreen.svg)
![](https://img.shields.io/badge/Support-Groovy,Java,Scala-brightgreen.svg)

## I. 安装

```sh
# 检查 Java 版本
$ java -version
# 下载安装包
$ curl -k -LO https://services.gradle.org/distributions/gradle-6.2.2-bin.zip
$ unzip gradle-6.2.2-bin.zip
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


## I. 工程目录

### II. gradle-wrapper.properties

便于在团队开发过程中统一 Gradle 构建的版本号

```
project
├── gradle
│   └── wrapper
│       ├── gradle-wrapper.jar
│       └── gradle-wrapper.properties
├── gradlew
└── gradlew.bat
```

```
# 下载的 Gradle 压缩包解压后存储的主目录
distributionBase=GRADLE_USER_HOME
# 相对于 distributionBase 解压后的 Gradle 压缩包路径
distributionPath=wrapper/dists
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
# Gradle 发行版压缩包下载地址
distributionUrl=https\://services.gradle.org/distributions/gradle-5.6.2-all.zip
```

### II. settings.gradle

子工程目录配置

```
project
└── settings.gradle
```

### II. build.gradle

```
project
└── build.gradle
```

```gradle
# Gradle 脚本自身需要使用的资源
buildscript {
    # 自定义属性
    ext {
        minJavaVersion = "8"
        gradleVersion = "$versions.gradle"
    }
    # 仓库地址
    repositories {
        mavenLocal()
        maven {
          url "http://maven.aliyun.com/nexus/content/groups/public"
        }
    }
    # 依赖
    dependencies {
        classpath "org.ajoberstar.grgit:grgit-core:$versions.grgit"
        classpath "com.github.ben-manes:gradle-versions-plugin:$versions.gradleVersionsPlugin"
        classpath "org.scoverage:gradle-scoverage:$versions.scoveragePlugin"
        classpath "com.github.jengelman.gradle.plugins:shadow:$versions.shadowPlugin"
        classpath "org.owasp:dependency-check-gradle:$versions.owaspDepCheckPlugin"
        classpath "com.diffplug.spotless:spotless-plugin-gradle:$versions.spotlessPlugin"
        classpath "com.github.spotbugs:spotbugs-gradle-plugin:$versions.spotbugsPlugin"
    }
}


// 所有项目共同所需的依赖
allprojects {
    repositories {
        mavenLocal()
    }
}

// 继承自 Delete, 相当于执行 Delete.delete(rootProject.buildDir)
task clean(type: Delete) {
    delete rootProject.buildDir
}

// 二进制插件: jar
apply plugin: "com.diffplug.gradle.spotless"
// 插件提供的扩展类型
spotless {
  scala {
    target 'streams/**/*.scala'
    scalafmt("$versions.scalafmt").configFile('checkstyle/.scalafmt.conf')
  }
}
```

自定义属性也可以单独放在一个文件, 如:

```gradle
# filename: version.gradle
ext {
    versionName = '1.0.0'
    versionCode = 1
}
```

通过 apply 引入:

```gradle
apply from: "version.gradle"

task printStringClass {
    println "versionName: ${versionName}, versionCode: ${versionCode}"
}
```

运行: `gradle task printStringClass`

!!! quote "[这一次彻底弄明白Gradle相关配置](https://mp.weixin.qq.com/s/mn4zMxLzzd7fPzCnjNsPcg)"


## I. Hello World

### II. 初始化工程

```sh
mkdir gradle-project
cd gradle-project
gradle init

Select type of project to generate:
  1: basic
  2: application
  3: library
  4: Gradle plugin
Enter selection (default: basic) [1..4]

Select build script DSL:
  1: Groovy
  2: Kotlin
Enter selection (default: Groovy) [1..2]

Project name (default: gradle-project):

> Task :init
Get more help with your project: https://guides.gradle.org/creating-new-gradle-builds

BUILD SUCCESSFUL in 41s
2 actionable tasks: 2 executed

tree .
.
├── build.gradle
├── gradle
│   └── wrapper
│       ├── gradle-wrapper.jar
│       └── gradle-wrapper.properties
├── gradlew
├── gradlew.bat
└── settings.gradle

2 directories, 6 files
```

### II. 创建 task(基本操作)

```sh
mkdir src
vim src/myfile.txt
Hello World!
```

```gradle
// filename: build.gradle

// 继承自 Copy
task copy(type: Copy, group: "Custom", description: "Copies sources to the dest directory") {
    from "src"
    into "dest"
}
```

```sh
gradle copy

BUILD SUCCESSFUL in 795ms
1 actionable task: 1 executed


cat dest/myfile.txt
Hello World!
```


```gradle
// 快速定义任务
task hello << {
    println 'Hello world!'
}

// 更多示例
task upper << {
    String someString = 'mY_nAmE'
    println "Original: " + someString
    println "Upper case: " + someString.toUpperCase()
}

task count << {
    4.times { print "$it " }
}
```

```sh
# -q: 日志级别
gradle -q hello
```

## I. 任务依赖

```gradle
task hello << {
    println 'Hello world!'
}

task intro(dependsOn: hello) << {
    println "I'm Gradle"
}
```

```sh
gradle -q intro
```

!!! quote "[Creating New Gradle Builds](https://guides.gradle.org/creating-new-gradle-builds/)"


## I. FAQ

1. Process 'Gradle Worker Daemon 1' finished with non-zero exit value 137
    - 问题原因: OutOfMemmoryError, Gradle 构建过程中内存耗尽, 导致 worker 进程退出
    - 解决方案: 增大内存

1. Cannot resolve placeholder 'M2_HOME' in value '${M2_HOME}/repo'
    - 问题原因: Maven 的 settings.xml 中配置了 `<localRepository>${M2_HOME}/repo</localRepository>`, 无法找到变量
