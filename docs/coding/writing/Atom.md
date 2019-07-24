# Atom

官方网站：<https://atom.io/>

!!! tip
    需提前下载并安装.NET Framework，下载地址：<https://dotnet.microsoft.com/download/dotnet-framework-runtime>，安装完成后重启。  

> Atom通过新建project来进行文件夹操作。

## 配置

- 显示空格，TAB，换行符：`File - Settings - Editor`，勾选`Show Invisibles`。  
- 更改Tab转换的空格数量：`File - Settings - Editor`，修改`Tab Length`为4。  
- 关闭自动补齐：`File - Settings - Packages - Core Packages - autocomplete-plus - Settings`，取消勾选`Show Suggestions On Keystroke`。  
- 更改主题：`File - Settings - 主题`。  

## 快捷键

- 预览：`Ctrl + Shift + M`  
- 字体放大：`Ctrl + Shift + =`  

## 插件

### 查找插件

官方地址：<https://atom.io/packages>

- [simplified-chinese-menu](https://atom.io/packages/simplified-chinese-menu): 汉化
- [atom-material-syntax](https://atom.io/themes/atom-material-syntax): 语法主题
- [atom-material-ui](https://atom.io/themes/atom-material-ui): UI主题
- [markdown-img-paste](https://atom.io/packages/markdown-img-paste): 图片粘贴
- [document-outline](https://atom.io/packages/document-outline): 标题列表
- [minimap](https://atom.io/packages/minimap): 代码缩略图
- [highlight-selected](https://atom.io/packages/highlight-selected)：选中高亮
- [minimap-highlight-selected](https://atom.io/packages/minimap-highlight-selected): 选中缩略图高亮
- [sublime-style-column-selection](https://atom.io/packages/sublime-style-column-selection): 列选择
- [atom-beautify](https://atom.io/packages/atom-beautify): 代码格式化
    - 选中代码 - `Ctrl + Shift + p` - `beautify language`

### 安装插件

#### 方式一

解压后直接将文件夹拷贝到路径：`C:\Users\<username>\.atom\packages`，如在剪贴板粘贴截图：`Ctrl + Shift + V`  

#### 方式二

```bash
apm config list  # 查看代理配置
apm config set strict-ssl false
apm config set http-proxy http://l0025xxxx:pass\@word@proxy.xxx.com:8080
apm config set https-proxy http://l0025xxxx:pass\@word@proxy.xxx.com:8080
apm install minimap  # 安装插件


# node -v  # 查看node.js版本
# npm -v  # 查看npm版本
# npm config list  # 查看代理配置
# npm config set proxy http://l0025xxxx:pass\@word@proxy.xxx.com:8080
# npm config set https-proxy http://l0025xxxx:pass\@word@proxy.xxx.com:8080
# npm install minimap -g  # 全局安装
```

!!! tip "提示"
    MAC中apm的位置为：`/Applications/Atom.app/Contents/Resources/app/apm/bin/apm`
