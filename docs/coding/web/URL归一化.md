---
title: URL归一化
---

# 前置条件

假设存在URL：`http://30thh.loc:8480/app/test%3F/a%3F+b;jsessionid=S%3F+ID?p+1=c+d&p+2=e+f#a`

应用程序部署在`/app`下。

对应servlet配置为：  
```xml
<servlet>
     <servlet-name>test</servlet-name>
     <servlet-class>TestServlet</servlet-class>
 </servlet>
 <servlet-mapping>
     <servlet-name>test</servlet-name>
     <url-pattern>/test%3F/*</url-pattern>
 </servlet-mapping>
```

# 运行结果

| Method | URL-Decoded | Result | Comments |
| --- | --- | --- | --- |
| getContextPath() | no | /app |  |
| getLocalAddr() |  | 127.0.0.1 |  |
| getLocalName() |  | 30thh.loc |  |
| getLocalPort() |  | 8480 |  |
| getMethod() |  | GET |  |
| getPathInfo() | yes | /a?+b | 如果servlet配置中的url-pattern不以*结束（如/test或*.jsp），或使用Spring，getPathInfo返回null。 |
| getProtocol() |  | HTTP/1.1 |  |
| getQueryString() | no | p+1=c+d&p+2=e+f |  |
| getRequestedSessionId() | no | S%3F+ID |  |
| getRequestURI() | no | /app/test%3F/a%3F+b;jsessionid=S+ID | requestURI = contextPath + servletPath + pathInfo |
| getRequestURL() | no | http://30thh.loc:8480/app/test%3F/a%3F+b;jsessionid=S+ID |  |
| getScheme() |  | http |  |
| getServerName() |  | 30thh.loc |  |
| getServerPort() |  | 8480 |  |
| getServletPath() | yes | /test? | 如果使用Spring，getServletPath返回context和session ID之间的部分，即/test?/a?+b |
| getParameterNames() | yes | [p 2, p 1] | “+”号仅在查询字符串中代表空格。 |
| getParameter("p 1") | yes | c d |  |
|  |  |  | 锚点“#a”不会被传输到服务器，仅在客户端浏览器中处理。 |
