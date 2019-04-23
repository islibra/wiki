---
title: CDATA
---

在XML中，`<`和`&`是非法的。  
使用`<![CDATA[xxx]]>`忽略XML解析，常用于嵌入其他语言如SQL。

# 示例：mybatis

```xml
<select id="allUserInfo" parameterType="java.util.HashMap" resultMap="userInfo1">
  <![CDATA[
  SELECT newsEdit,newsId, newstitle FROM shoppingGuide  WHERE 1=1  AND  newsday > #{startTime} AND newsday <= #{endTime}
  ]]>
  <if test="etidName!=''">
   AND newsEdit=#{etidName}
  </if>
</select>
```
