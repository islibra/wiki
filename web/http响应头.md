# Content-Security-Policy

CSP，通过白名单进行资源加载限制，防止XSS攻击。

默认值Content-Security-Policy: default-src 'self'

特殊值  
- 'unsafe-inline'：允许执行页面内嵌的&lt;script>标签和事件监听函数
- 'unsafe-eval'：允许将字符串当作代码执行，比如使用eval、setTimeout、setInterval和Function等函数。

## 示例代码

在web.xml中增加filter：

```xml
    <filter>
        <filter-name>SecurityFilter</filter-name>
        <filter-class>com.test.filter.SecurityFilter</filter-class>
        <init-param>
            <param-name>Content_Security_Policy_enable</param-name>
            <param-value>true</param-value>
        </init-param>
        <init-param>
            <param-name>Content_Security_Policy</param-name>
            <param-value>default-src 'self' 'unsafe-inline' 'unsafe-eval'</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>SecurityFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
```

```java
package com.test.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

/**
 * HTTP头过滤器
 * @author lixiaolong
 */
public class SecurityFilter implements Filter {

    private String Content_Security_Policy_enable = "true";

    private String Content_Security_Policy = "default-src 'self' 'unsafe-inline' 'unsafe-eval'";

    public void init(FilterConfig filterConfig) throws ServletException {

        String configValue = null;

        //"Content-Security-Policy"
        configValue = filterConfig.getInitParameter("Content_Security_Policy_enable");
        if ( configValue != null ) {
            Content_Security_Policy_enable = configValue;
        }
        configValue = filterConfig.getInitParameter("Content_Security_Policy");
        if ( configValue != null ) {
            Content_Security_Policy = configValue;
        }
    }

    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        HttpServletResponse res = (HttpServletResponse)response;

        if("true".equals(Content_Security_Policy_enable))
        {
            res.addHeader("Content-Security-Policy", Content_Security_Policy);
        }

        chain.doFilter(request, response);
    }

    public void destroy() {

    }
}
```
