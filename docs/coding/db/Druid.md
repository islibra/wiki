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

if(statement instanceof SQLSelectStatement)
{
    SQLSelect select = ((SQLSelectStatement) statement).getSelect();
    SQLSelectQuery query = select.getQuery();
    if(query instanceof SQLSelectQueryBlock)
    {
        //解析Table
        SQLTableSource table = ((SQLSelectQueryBlock) query).getFrom();
        System.out.println("getFrom: " + table);
        //关联查询
        if(table instanceof SQLJoinTableSource)
        {
            SQLJoinTableSource joinTable=(SQLJoinTableSource)table;
            String joinType=joinTable.getJoinType().toString();
            System.out.println("joinType: " + joinType);  //关联类型：JOIN/COMMA
            System.out.println("getLeft: " + joinTable.getLeft());  //左表
            System.out.println("getRight: " + joinTable.getRight());  //右表
            SQLExpr expr = joinTable.getCondition();  //关联条件
            System.out.println("getCondition: " + expr);
        }

        System.out.println("");
        //查询列
        List<SQLSelectItem> mysqlSelectList = ((SQLSelectQueryBlock) query).getSelectList();
        System.out.println("getSelectList: " + mysqlSelectList);
        for(SQLSelectItem sqlSelectItem : mysqlSelectList)
        {
            //select *
            if (sqlSelectItem.getExpr() instanceof SQLAllColumnExpr)
            {
                System.out.println("getExpr: " + sqlSelectItem.getExpr());
            }
            //聚合函数
            else if(sqlSelectItem.getExpr() instanceof SQLAggregateExpr)
            {
                System.out.println("getMethodName: " + ((SQLAggregateExpr) sqlSelectItem.getExpr()).getMethodName());  //函数名称
                System.out.println("getArguments: " + ((SQLAggregateExpr) sqlSelectItem.getExpr()).getArguments());  //参数列表
            }
            else if (sqlSelectItem.getExpr() instanceof SQLPropertyExpr)
            {
                System.out.println("getExpr: " + sqlSelectItem.getExpr());
            }
            else
            {
                System.out.println("item: " + sqlSelectItem);
            }
        }

        System.out.println("");
        //查询条件
        SQLExpr expr = ((SQLSelectQueryBlock) query).getWhere();
        System.out.println("getWhere: " + expr);
        if (expr instanceof SQLBinaryOpExpr)
        {
            //表达式
            SQLBinaryOpExpr bexpr = (SQLBinaryOpExpr)expr;
            System.out.println("getLeft: " + bexpr.getLeft());
            System.out.println("getRight: " + bexpr.getRight());
            System.out.println("getOperator: " + bexpr.getOperator());  //BooleanAnd\BooleanOr
            if (bexpr.getLeft() instanceof SQLBinaryOpExpr)
            {
                SQLBinaryOpExpr bexprL = (SQLBinaryOpExpr)bexpr.getLeft();
                System.out.println("LgetLeft: " + bexprL.getLeft());
                //字符串值
                if (bexprL.getRight() instanceof SQLCharExpr)
                {
                    System.out.println("LgetRight: " + ((SQLCharExpr)bexprL.getRight()).toString());
                }
                //Equality
                if (SQLBinaryOperator.Equality == bexprL.getOperator())
                {
                    System.out.println("LgetOperator: =");
                }
            }
            if (bexpr.getRight() instanceof SQLBinaryOpExpr)
            {
                SQLBinaryOpExpr bexprR = (SQLBinaryOpExpr)bexpr.getRight();
                System.out.println("RgetLeft: " + bexprR.getLeft());
                //数字值
                if (bexprR.getRight() instanceof SQLIntegerExpr)
                {
                    System.out.println("RgetRight: " + ((SQLIntegerExpr)bexprR.getRight()).getNumber().longValue());
                }
                System.out.println("RgetOperator: " + bexprR.getOperator());  //GreaterThan
            }
        }
        else if(expr instanceof SQLInListExpr)
        {
            //IN子句
            SQLInListExpr inexpr = (SQLInListExpr)expr;
            SQLExpr exprL =  inexpr.getExpr();
            System.out.println("in getExpr: " + exprL);
            System.out.println("toMySqlString: " + SQLUtils.toMySqlString(inexpr));  //将IN转换成key in (values)
        }

        System.out.println("");
        //排序
        SQLOrderBy orderby = ((SQLSelectQueryBlock) query).getOrderBy();
        if (orderby != null )
        {
            List<SQLSelectOrderByItem> orderbyItems = orderby.getItems();
            for (SQLSelectOrderByItem orderitem : orderbyItems)
            {
                System.out.println("getExpr: " + orderitem.getExpr());
                if (SQLOrderingSpecification.ASC==orderitem.getType() || SQLOrderingSpecification.DESC==orderitem.getType())
                {
                    System.out.println("getType: " + orderitem.getType());  //ASC\DESC
                }
            }
        }

        System.out.println("");
        //分页
        SQLLimit limit = ((SQLSelectQueryBlock) query).getLimit();
        if (limit != null)
        {
            System.out.println("getOffset: " + limit.getOffset());
            System.out.println("getRowCount: " + limit.getRowCount());
        }
    }
}

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
