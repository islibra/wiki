---
title: Druid
date: 2018-09-16 13:51:33
categories: db
tags:
---

# SQL Parser


## Parser


### Lexer词法分析

Lexer中拥有词汇表，即Keywords。

```java
protected Keywords keywods = Keywords.DEFAULT_KEYWORDS;
```

`DEFAULT_KEYWORDS`是一个Map<String, Token>，`Token`是词汇的枚举类，包含`SELECT\INSERT\FROM\WHERE`等。

`nextToken()`从SQL语句解析出下一个单词。
`token()`返回上一次解析的单词的Token类型。
`stringVal()`获取标识符(Identifier)类型的值。


### Parser语法分析

在`SQLStatementParser`的`parseStatement`方法中通过调用`token()`方法，解析`SQLStatement`。如果Token类型为`SELECT`，则调用`parseSelect()`方法解析`SQLSelectStatement`。


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

System.out.println("getColumns:" + visitor.getColumns());
System.out.println("getTables:" + visitor.getTables());
System.out.println("getParameters:" + visitor.getParameters());
System.out.println("getOrderByColumns:" + visitor.getOrderByColumns());
System.out.println("getGroupByColumns:" + visitor.getGroupByColumns());

// 创建表语句中查找主键和自增字段
if(statement instanceof MySqlCreateTableStatement)
{
    MySqlCreateTableStatement createTableStatement = (MySqlCreateTableStatement)statement;
    List<SQLTableElement> tableElementList = createTableStatement.getTableElementList();
    // 找出主键
    for (SQLTableElement element : tableElementList) {
        // 单独定义的主键，PRIMARY KEY (name，id)
        if (element instanceof MySqlPrimaryKey) {
            List<SQLExpr> columns = ((MySqlPrimaryKey) element).getColumns();
            System.out.println("PrimaryKey: " + columns.get(0).toString());
        }

        // 字段定义后面 id int primary key,
        if (element instanceof SQLColumnDefinition) {
            SQLColumnDefinition columnDefinition = (SQLColumnDefinition) element;
            // 自增长列名称
            String columnName = columnDefinition.getName().toString();
            //判断id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY
            List<SQLColumnConstraint> constraints = columnDefinition.getConstraints();
            for (SQLColumnConstraint constraintTmp : constraints) {
                if (constraintTmp instanceof SQLColumnPrimaryKey) {
                    System.out.println("Constraint PrimaryKey: " + columnName);
                }
            }

            // 自增字段
            if (columnDefinition.isAutoIncrement())
            {
                System.out.println("AutoIncrement: " + columnName);
            }
            
            // 字段类型
            SQLDataType sqlDataType = columnDefinition.getDataType();
            if (sqlDataType != null) {
                System.out.println("DataType: " + sqlDataType.getName());
            }
        }
    }
}
```


[官方文档](https://github.com/alibaba/druid/wiki/SQL-Parser)
