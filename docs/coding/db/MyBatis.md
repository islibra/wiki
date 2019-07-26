# MyBatis

官方网站: <http://www.mybatis.org>

1. 在数据库驱动jar的基础上引入mybatis的jar。
1. 创建SqlMapConfig.xml，定义数据库连接信息，映射文件。
    - properties加载外部配置文件，使用`${key}`引用。
1. 创建映射文件，配置语句和bean的映射关系。
    - 可以使用sql创建片段，并在select中使用include包含。
1. 应用程序加载配置文件，使用SqlMapClient接口进行数据操作。
    - queryForObject()
    - queryForMap()
    - queryForList()
1. 查询参数：`select * from users where USERNAME=#VARCHAR#;`，在查询语句中增加parameterClass。
1. 多个参数使用Map传递：`where REALNAME=#realName:VARCHAR# and MOBILE=#mobile:VARCHAR#`
1. 使用`$xxx$`将变量直接插入到sql语句中：`where email like '%$value$%'`，相当于`where email like concat('%', #value#, '%')`


???+ quote "参考链接"
    [浅谈mybatis如何半自动化解耦](http://www.cnblogs.com/wangjiming/p/10384975.html)
