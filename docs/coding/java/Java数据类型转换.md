---
title: Java数据类型转换
date: 2018-09-08 11:26:54
categories: java
tags:
---

# String与Date

## 时间格式

| Date and Time Pattern | Result |
| --- | --- |
| "yyyy.MM.dd G 'at' HH:mm:ss z" | 2001.07.04 AD at 12:08:56 PDT |
| "EEE, MMM d, ''yy" | Wed, Jul 4, '01 |
| "h:mm a" | 12:08 PM |
| "hh 'o''clock' a, zzzz" | 12 o'clock PM, Pacific Daylight Time |
| "K:mm a, z" | 0:08 PM, PDT |
| "yyyyy.MMMMM.dd GGG hh:mm aaa" | 02001.July.04 AD 12:08 PM |
| "EEE, d MMM yyyy HH:mm:ss Z" | Wed, 4 Jul 2001 12:08:56 -0700 |
| "yyMMddHHmmssZ" | 010704120856-0700 |
| "yyyy-MM-dd'T'HH:mm:ss.SSSZ" | 2001-07-04T12:08:56.235-0700 |
| "yyyy-MM-dd'T'HH:mm:ss.SSSXXX" | 2001-07-04T12:08:56.235-07:00 |
| "YYYY-'W'ww-u" | 2001-W27-3 |

## String转Date

```java
DateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss.SSS");
Date date = df.parse(strTime);
```

## Date转String

```java
DateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss.SSS");
String tsStr = sdf.format(time);
```


# 将List转换为以逗号分隔的字符串

```java
List<String> cities = Arrays.asList("Shenzhen", "Beijing", "Shanghai");
String citiesCommaSeparated = String.join(",", cities);
```
