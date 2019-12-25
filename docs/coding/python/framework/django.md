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

> 在mysite/settings.py中添加`ALLOWED_HOSTS = ['x.x.x.x']`

## 0x03 启动服务器

`python manage.py runserver [ip:port]`

## 0x04 创建应用

`python manage.py startapp myapp`

## 0x05_URL

```python tab="mysite/urls.py"
from django.urls import path
from myapp import views

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

!!! faq "是否还存在路径跨越?"
    ```python
    urlpatterns = [
        url('^xxx/yyy$', Xxx.as_view()),
        url('^aaa/bbb$', Aaa.as_view())
    ]
    ```

## 0x06 视图

```python tab="myapp/views.py"
from django.http import HttpResponse

def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")
```


!!! quote "中文文档"
    <https://docs.djangoproject.com/zh-hans/2.2/>


## 数据库配置

> Python内置SQLite

```python tab="mysite/settings.py"
# 'django.db.backends.sqlite3'
# 'django.db.backends.postgresql'
# 'django.db.backends.mysql'
# 'django.db.backends.oracle'
DATABASES['default']['ENGINE'] = 'xxx'
# 数据库名称, 如SQLite: os.path.join(BASE_DIR, 'db.sqlite3')
DATABASES['default']['NAME'] = 'xxx'
DATABASES['default']['USER'] = 'xxx'
DATABASES['default']['PASSWORD'] = 'xxx'
```

### 模型定义

```python tab="mysite/models.py"
from django.db import models
from django.contrib.auth.models import AbstractUser

class Question(models.Model):
    # 字段名称: question_text
    question_text = models.CharField(max_length=200)
    pub_date = models.DateTimeField('date published')

class Choice(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    choice_text = models.CharField(max_length=200)
    votes = models.IntegerField(default=0)
```

### INSERT

```python
from blog.models import Blog
b = Blog(name='Beatles Blog', tagline='All the latest Beatles news.')
b.save()
```

### UPDATE

```python
b5.name = 'New name'
b5.save()
```

### SELECT

```python
one_entry = Entry.objects.get(pk=1)
all_entries = Entry.objects.all()
filter_entries = Entry.objects.filter(pub_date__year=2006)
Entry.objects.filter(
    headline__startswith='What'
).exclude(
    pub_date__gte=datetime.date.today()
).filter(
    pub_date__gte=datetime.date(2005, 1, 30)
)
```

## 日志

Python内置logging模块


!!! quote "参考链接: [Django文档目录](https://docs.djangoproject.com/zh-hans/3.0/contents/)"
