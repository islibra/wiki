# SQL Parser

## Parser

### Parser语法分析
### Lexer词法分析

## AST抽象语法树

### 节点类型

+ interface SQLObject {}
+ interface SQLExpr extends SQLObject {}

  + interface SQLName extends SQLExpr {}
  
    + class SQLIdentifierExpr implements SQLName  //如`ID = 3`的`ID`
    + class SQLPropertyExpr implements SQLName  //如`A.ID = 3`的`A.ID`
    
  + class SQLBinaryOpExpr implements SQLExpr  //如`ID = 3`是一个SQLBinaryOpExpr，left是ID (SQLIdentifierExpr)，right是3 (SQLIntegerExpr)
  + class SQLIntegerExpr extends SQLNumericLiteralExpr implements SQLValuableExpr  //如`ID = 3`的`3`是一个SQLIntegerExpr
  + class SQLCharExpr extends SQLTextLiteralExpr implements SQLValuableExpr  //如`NAME = 'jobs'`的`'jobs'`是一个SQLCharExpr

+ interface SQLStatement extends SQLObject {}

  + class SQLSelectStatement implements SQLStatement
  + class SQLUpdateStatement implements SQLStatement
  + class SQLDeleteStatement implements SQLStatement
  + class SQLInsertStatement implements SQLStatement
+ class SQLCreateTableStatement extends SQLStatementImpl
  
+ interface SQLTableSource extends SQLObject {}

  + class SQLTableSourceImpl extends SQLObjectImpl implements SQLTableSource
  
    + class SQLExprTableSource extends SQLTableSourceImpl  //如`select * from emp where i = 3`，的`from emp`是一个SQLExprTableSource，其中`expr`是一个`name=emp`的SQLIdentifierExpr
    + class SQLJoinTableSource extends SQLTableSourceImpl  //如`select * from emp e inner join org o on e.org_id = o.id`，其中left `'emp e'` 是一个SQLExprTableSource，right `'org o'`也是一个SQLExprTableSource，condition `'e.org_id = o.id'`是一个SQLBinaryOpExpr
    + SQLSubqueryTableSource extends SQLTableSourceImpl  //如`select * from (select * from temp) a`，这里第一层`from(...)`是一个SQLSubqueryTableSource

+ class SQLSelect extends SQLObject {}
+ interface SQLSelectQuery extends SQLObject {}
+ class SQLSelectQueryBlock extends SQLObject {}
+ class SQLUnionQuery implements SQLSelectQuery

```java
final String dbType = JdbcConstants.MYSQL;  //可以是ORACLE、POSTGRESQL、SQLSERVER、ODPS等
String sql = "select * from t";
List<SQLStatement> stmtList = SQLUtils.parseStatements(sql, dbType);  //生成SQL语句
SQLExpr expr = SQLUtils.toSQLExpr("id=3", dbType);  //生成表达式
```

## Visitor

+ OutputVisitor用来把AST输出为字符串
+ WallVisitor分析SQL语意来防御SQL注入攻击
+ ParameterizedOutputVisitor用来合并未参数化的SQL进行统计
+ EvalVisitor用来对SQL表达式求值
+ ExportParameterVisitor用来提取SQL中的变量参数
+ SchemaStatVisitor用来统计SQL中使用的表、字段、过滤条件、排序表达式、分组表达式
+ SQL格式化 Druid内置了基于语义的SQL格式化功能

## 典型操作

```java
String sql = "select * from user order by id";

// 新建 MySQL Parser
SQLStatementParser parser = new MySqlStatementParser(sql);

// 使用Parser解析生成AST，这里SQLStatement就是AST
SQLStatement statement = parser.parseStatement();

// 使用visitor来访问AST
MySqlSchemaStatVisitor visitor = new MySqlSchemaStatVisitor();
statement.accept(visitor);

System.out.println(visitor.getColumns());
System.out.println(visitor.getOrderByColumns());
```