# django

## 0x00 查看django版本

`python -m django --version`

## 0x01 创建web应用项目

`django-admin startproject mysite`

## 0x02 项目组织结构：

```
mysite/
    manage.py  # 用户交互命令行
    mysite/  # python package
        __init__.py  # empty
        settings.py  # 配置文件
        urls.py  # 定义接口
        wsgi.py  # 部署入口
    myapp/  # 由python manage.py startapp myapp命令创建
        __init__.py
        admin.py
        apps.py
        migrations/
            __init__.py
        models.py
        tests.py
        views.py
```

## 0x03 启动服务器

`python manage.py runserver [ip:port]`

## 0x04 创建应用

`python manage.py startapp myapp`

## 0x05 视图

```python
from django.http import HttpResponse

def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")
```

## 0x06_URL

```python tab="创建myapp/urls.py"
from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
]
```

```python tab="include到服务器"
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('polls/', include('polls.urls')),
    path('admin/', admin.site.urls),
]
```


!!! quote "中文文档"
    <https://docs.djangoproject.com/zh-hans/2.2/>
