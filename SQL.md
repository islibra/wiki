> **Tips:** SQL 对大小写不敏感！


# DML

+ SELECT 列名称 FROM 表名称
    + SELECT **DISTINCT** column1, column2, ... FROM table_name;  //去重
    + SELECT ID **AS** CUSTOMER_ID, NAME **AS** CUSTOMER_NAME FROM CUSTOMERS;  //列别名
    + SELECT C.ID, C.NAME, C.AGE, O.AMOUNT FROM CUSTOMERS AS C, ORDERS AS O WHERE C.ID = O.CUSTOMER_ID;  //表别名
+ UPDATE 表名称 SET 列1名称 = 新值1[, 列2名称 = 新值2] WHERE 列名称 = 某值
+ DELETE FROM 表名称 WHERE 列名称 = 值
+ INSERT INTO table_name [(列1, 列2,...)] VALUES (值1, 值2,....)

> **WARNING!** DELETE不加WHERE子句就会删除表中全部数据！

## WHERE子句

SELECT 列名称 FROM 表名称 **WHERE 列 运算符 值**

### 运算符用法：

+ =  !=  >  >=  <  <=，例：
    + `WHERE City='Beijing'`
    + `WHERE Year>1965`
+ BETWEEN，例：`SELECT column_name(s) FROM table_name WHERE column_name BETWEEN value1 AND value2;`，适用于文本、数值或日期。
+ LIKE，％ 百分号表示零个，一个或多个字符；_ 下划线表示单个字符；[charlist] 表示字符列中的任一字符；[^charlist]或[!charlist] 表示不在字符列中的任一字符。例：
    + `SELECT * FROM Customers WHERE CustomerName LIKE 'a%';`
    + `SELECT * FROM Customers WHERE CustomerName LIKE '_r%';`
    + `SELECT * FROM Persons WHERE City NOT LIKE '%lon%'`
    + `SELECT * FROM Persons WHERE City LIKE '[ALN]%'`，以A或L或N开头的任意字符串
+ IS，例：
    + 测试空值：`SELECT column_names FROM table_name WHERE column_name IS [NOT] NULL;`
+ IN，例：`SELECT column_name(s) FROM table_name WHERE column_name IN (value1,value2,...);`

> **Tips:** 文本使用单引号，数值不使用引号！

### AND和OR

+ SELECT * FROM Persons WHERE FirstName='Thomas' AND LastName='Carter'
+ SELECT * FROM Persons WHERE firstname='Thomas' OR lastname='Carter'
+ SELECT * FROM Persons WHERE (FirstName='Thomas' OR FirstName='William') AND LastName='Carter'

## ORDER BY

SELECT 列名称 FROM 表名称 **ORDER BY 列1 [ASC/DESC], 列2 [ASC/DESC]**

## TOP子句

+ SQL Server: `SELECT TOP number|percent column_name(s) FROM table_name WHERE condition;`，例：
    + SELECT TOP 2 * FROM Persons
    + SELECT TOP 50 PERCENT * FROM Persons
+ MySQL: `SELECT column_name(s) FROM table_name LIMIT number;`，例：
    + SELECT User from user limit 2;  /* 只查询2条数据 */
    + SELECT User from user limit 2,3;  /* 从偏移量2开始查询3条数据，偏移量从0开始 */
+ Oracle: `SELECT column_name(s) FROM table_name WHERE ROWNUM <= number;`

> **Tips:** 如果只查询一条记录，可以加上LIMIT 1，避免全表扫描。在偏移量大的时候limit执行效率降低，应优先使用where子句，配合limit使用。

## 函数

SELECT function(列) FROM 表

```sql
SELECT AVG(OrderPrice) AS OrderAverage FROM Orders;
SELECT Customer FROM Orders WHERE OrderPrice>(SELECT AVG(OrderPrice) FROM Orders)
SELECT COUNT(Customer) AS CustomerNilsen FROM Orders WHERE Customer='Carter'
/* 类似用法：FIRST\LAST\MAX\MIN\SUM\UCASE\LCASE\LEN */
/* 获取子字符串 */
SELECT MID(City,1,3) as SmallCity FROM Persons;  /* SELECT MID(column_name,start[,length]) FROM table_name */
/* 把数值字段舍入为指定的小数位数 */
SELECT ProductName, ROUND(UnitPrice,0) as UnitPrice FROM Products;  /* SELECT ROUND(column_name,decimals) FROM table_name */
/* 获取当前时间 */
SELECT NOW() FROM table_name;
/* 格式化 */
SELECT ProductName, UnitPrice, FORMAT(Now(),'YYYY-MM-DD') as PerDate FROM Products;
```

### GROUP BY

SELECT column_name1, column_name2, aggregate_function(column_name3) FROM table_name GROUP BY column_name1, column_name2;
```sql
SELECT Customer,SUM(OrderPrice) FROM Orders GROUP BY Customer;
```

### HAVING

WHERE 关键字无法与合计函数一起使用，HAVING 子句对GROUP BY子句过滤。
SELECT column_name, aggregate_function(column_name) FROM table_name WHERE column_name operator value GROUP BY column_name HAVING aggregate_function(column_name) operator value;

```sql
SELECT Customer,SUM(OrderPrice) FROM Orders GROUP BY Customer HAVING SUM(OrderPrice)<2000;
```

## JOIN

+ [INNER] JOIN: `SELECT column_name(s) FROM table_name1 INNER JOIN table_name2 ON table_name1.column_name=table_name2.column_name;`，所有表中的数据都匹配（不为空）才会显示。
    + 例：`SELECT Persons.LastName, Persons.FirstName, Orders.OrderNo FROM Persons INNER JOIN Orders ON Persons.Id_P = Orders.Id_P;`
    + 相当于：`SELECT Persons.LastName, Persons.FirstName, Orders.OrderNo FROM Persons, Orders WHERE Persons.Id_P = Orders.Id_P;`
+ LEFT [OUTER] JOIN: `SELECT column_name(s) FROM table_name1 LEFT JOIN table_name2 ON table_name1.column_name=table_name2.column_name`，从左表返回所有的行。
+ RIGHT [OUTER] JOIN: `SELECT column_name(s) FROM table_name1 RIGHT JOIN table_name2 ON table_name1.column_name=table_name2.column_name`，从右表返回所有的行。
+ FULL [OUTER] JOIN: `SELECT column_name(s) FROM table_name1 FULL JOIN table_name2 ON table_name1.column_name=table_name2.column_name`，返回所有表中的所有行。

## UNION

> **WARNING!** UNION用于合并两个或多个SELECT语句的结果集，必须拥有相同数量、类型、顺序的列。

+ UNION: `SELECT column_name(s) FROM table_name1 UNION SELECT column_name(s) FROM table_name2;`，去除重复值。
+ UNION ALL: `SELECT column_name(s) FROM table_name1 UNION ALL SELECT column_name(s) FROM table_name2;`，保留全部值。

> **Tips1:** 结果集中的列名总是等于 UNION 中第一个 SELECT 语句中的列名。

> **Tips2:** 跨表查询的方法：
> + SELECT column_name(s) FROM table_name WHERE column_name IN (SELECT STATEMENT);
> + SELECT Orders.OrderID, Customers.CustomerName, Orders.OrderDate FROM Orders INNER JOIN Customers ON Orders.CustomerID=Customers.CustomerID;
> + SELECT Customers.CustomerName, Orders.OrderID FROM Customers LEFT JOIN Orders ON Customers.CustomerID = Orders.CustomerID ORDER BY Customers.CustomerName;
> + SELECT Orders.OrderID, Employees.LastName, Employees.FirstName FROM Orders RIGHT JOIN Employees ON Orders.EmployeeID = Employees.EmployeeID ORDER BY Orders.OrderID;
> + SELECT City, Country FROM Customers WHERE Country='Germany' UNION SELECT City, Country FROM Suppliers WHERE Country='Germany' ORDER BY City;

## 复制表数据

+ SELECT INTO: `SELECT column_name(s) INTO new_table_name [IN externaldatabase] FROM old_tablename;`，可以使用IN关键字拷贝到另一个数据库中。例：
    + SELECT * INTO CustomersBackup2013 FROM Customers WHERE Country='Germany';
+ INSERT INTO SELECT
    + INSERT INTO Customers (CustomerName, Country) SELECT SupplierName, Country FROM Suppliers WHERE Country='Germany';


# DDL

+ CREATE DATABASE database_name
+ ALTER DATABASE
+ DROP DATABASE database_name
+ CREATE TABLE Persons
(
PersonID int,
LastName varchar(255),
FirstName varchar(255),
Address varchar(255),
City varchar(255)
);
+ ALTER TABLE
    + ALTER TABLE table_name ADD column_name datatype
    + ALTER TABLE table_name DROP COLUMN column_name
    + ALTER TABLE table_name ALTER COLUMN column_name datatype，SQL Server
    + ALTER TABLE table_name MODIFY COLUMN column_name datatype，Oracle
+ DROP TABLE table_name
+ CREATE INDEX index_name ON table_name (column_name)
+ DROP INDEX
```sql
/* Microsoft Access */
DROP INDEX index_name ON table_name
/* MS SQL Server */
DROP INDEX table_name.index_name
/* Oracle */
DROP INDEX index_name
/* MySQL */
ALTER TABLE table_name DROP INDEX index_name
```
+ TRUNCATE TABLE table_name，清空表中数据。

## 约束

### NOT NULL，字段非空。例：

```sql
CREATE TABLE Persons
(
Id_P int NOT NULL,
LastName varchar(255) NOT NULL,
FirstName varchar(255),
Address varchar(255),
City varchar(255)
)
```

### UNIQUE，字段唯一。例：

```sql
/* MySQL */
CREATE TABLE Persons
(
Id_P int NOT NULL,
LastName varchar(255) NOT NULL,
FirstName varchar(255),
Address varchar(255),
City varchar(255),
UNIQUE (Id_P)
)

/* SQL Server / Oracle / MS Access */
CREATE TABLE Persons
(
P_Id int NOT NULL UNIQUE,
LastName varchar(255) NOT NULL,
FirstName varchar(255),
Address varchar(255),
City varchar(255)
)

/* 命名 UNIQUE 约束，并为多个列定义 UNIQUE 约束，MySQL / SQL Server / Oracle / MS Access */
CREATE TABLE Persons
(
P_Id int NOT NULL,
LastName varchar(255) NOT NULL,
FirstName varchar(255),
Address varchar(255),
City varchar(255),
CONSTRAINT uc_PersonID UNIQUE (P_Id,LastName)
)

/* 增加约束，MySQL / SQL Server / Oracle / MS Access */
ALTER TABLE Persons ADD UNIQUE (Id_P);
ALTER TABLE Persons ADD CONSTRAINT uc_PersonID UNIQUE (P_Id,LastName)

/* 撤销 UNIQUE 约束，MySQL */
ALTER TABLE Persons DROP INDEX uc_PersonID
/* SQL Server / Oracle / MS Access */
ALTER TABLE Persons DROP CONSTRAINT uc_PersonID
```

### PRIMARY KEY，主键，唯一，非空，有且只有一个主键字段。例：

```sql
/* MySQL */
CREATE TABLE Persons
(
Id_P int NOT NULL,
LastName varchar(255) NOT NULL,
FirstName varchar(255),
Address varchar(255),
City varchar(255),
PRIMARY KEY (Id_P)
)

/* SQL Server / Oracle / MS Access */
CREATE TABLE Persons
(
Id_P int NOT NULL PRIMARY KEY,
LastName varchar(255) NOT NULL,
FirstName varchar(255),
Address varchar(255),
City varchar(255)
)

/* 命名 PRIMARY KEY 约束，并为多个列定义 PRIMARY KEY 约束，MySQL / SQL Server / Oracle / MS Access */
CREATE TABLE Persons
(
Id_P int NOT NULL,
LastName varchar(255) NOT NULL,
FirstName varchar(255),
Address varchar(255),
City varchar(255),
CONSTRAINT pk_PersonID PRIMARY KEY (Id_P,LastName)
)

/* 增加主键，MySQL / SQL Server / Oracle / MS Access，增加主键的字段必须在创建表时NOT NULL */
ALTER TABLE Persons ADD PRIMARY KEY (Id_P)
ALTER TABLE Persons ADD CONSTRAINT pk_PersonID PRIMARY KEY (Id_P,LastName)

/* 撤销 PRIMARY KEY 约束，MySQL */
ALTER TABLE Persons DROP PRIMARY KEY
/* SQL Server / Oracle / MS Access */
ALTER TABLE Persons DROP CONSTRAINT pk_PersonID
```

### FOREIGN KEY，外键，指向另一个表中的 PRIMARY KEY。例：

```sql
/* MySQL */
CREATE TABLE Orders
(
Id_O int NOT NULL,
OrderNo int NOT NULL,
Id_P int,
PRIMARY KEY (Id_O),
FOREIGN KEY (Id_P) REFERENCES Persons(Id_P)
)

/* SQL Server / Oracle / MS Access */
CREATE TABLE Orders
(
O_Id int NOT NULL PRIMARY KEY,
OrderNo int NOT NULL,
P_Id int FOREIGN KEY REFERENCES Persons(P_Id)
)

/* 命名 FOREIGN KEY 约束，并为多个列定义 FOREIGN KEY 约束，MySQL / SQL Server / Oracle / MS Access */
CREATE TABLE Orders
(
O_Id int NOT NULL,
OrderNo int NOT NULL,
P_Id int,
PRIMARY KEY (O_Id),
CONSTRAINT fk_PerOrders FOREIGN KEY (P_Id) REFERENCES Persons(P_Id)
)

/* 增加 FOREIGN KEY 约束，MySQL / SQL Server / Oracle / MS Access */
ALTER TABLE Orders ADD FOREIGN KEY (Id_P) REFERENCES Persons(Id_P)
ALTER TABLE Orders ADD CONSTRAINT fk_PerOrders FOREIGN KEY (P_Id) REFERENCES Persons(P_Id)

/* 撤销 FOREIGN KEY 约束，MySQL */
ALTER TABLE Orders DROP FOREIGN KEY fk_PerOrders
/* SQL Server / Oracle / MS Access */
ALTER TABLE Orders DROP CONSTRAINT fk_PerOrders
```

### CHECK，限制列中的值的范围。例：

```sql
/* My SQL */
CREATE TABLE Persons
(
Id_P int NOT NULL,
LastName varchar(255) NOT NULL,
FirstName varchar(255),
Address varchar(255),
City varchar(255),
CHECK (Id_P>0)
)

/* SQL Server / Oracle / MS Access */
CREATE TABLE Persons
(
Id_P int NOT NULL CHECK (Id_P>0),
LastName varchar(255) NOT NULL,
FirstName varchar(255),
Address varchar(255),
City varchar(255)
)

/* 命名 CHECK 约束，并为多个列定义 CHECK 约束，MySQL / SQL Server / Oracle / MS Access */
CREATE TABLE Persons
(
Id_P int NOT NULL,
LastName varchar(255) NOT NULL,
FirstName varchar(255),
Address varchar(255),
City varchar(255),
CONSTRAINT chk_Person CHECK (Id_P>0 AND City='Sandnes')
)

/* 新增CHECK约束，MySQL / SQL Server / Oracle / MS Access */
ALTER TABLE Persons ADD CHECK (Id_P>0)
ALTER TABLE Persons ADD CONSTRAINT chk_Person CHECK (Id_P>0 AND City='Sandnes')

/* 撤销 CHECK 约束，MySQL */
ALTER TABLE Persons DROP CHECK chk_Person
/* SQL Server / Oracle / MS Access */
ALTER TABLE Persons DROP CONSTRAINT chk_Person
```

### DEFAULT，向列中插入默认值。例：

```sql
/* MySQL / SQL Server / Oracle / MS Access */
CREATE TABLE Persons
(
Id_P int NOT NULL,
LastName varchar(255) NOT NULL,
FirstName varchar(255),
Address varchar(255),
City varchar(255) DEFAULT 'Sandnes'
)

/* 自动插入系统值 */
CREATE TABLE Orders
(
Id_O int NOT NULL,
OrderNo int NOT NULL,
Id_P int,
OrderDate date DEFAULT GETDATE()
)

/* 新增 DEFAULT 约束，MySQL */
ALTER TABLE Persons ALTER City SET DEFAULT 'SANDNES'
/* SQL Server / Oracle / MS Access */
ALTER TABLE Persons ALTER COLUMN City SET DEFAULT 'SANDNES'

/* 撤销 DEFAULT 约束，MySQL */
ALTER TABLE Persons ALTER City DROP DEFAULT
/* SQL Server / Oracle / MS Access */
ALTER TABLE Persons ALTER COLUMN City DROP DEFAULT
```

## 自增字段

### MySQL

```sql
CREATE TABLE Persons
(
P_Id int NOT NULL AUTO_INCREMENT,  /* 默认起始值为1，递增1 */
LastName varchar(255) NOT NULL,
FirstName varchar(255),
Address varchar(255),
City varchar(255),
PRIMARY KEY (P_Id)
)

/* 修改起始值 */
ALTER TABLE Persons AUTO_INCREMENT=100

/* 添加记录时不指定自增字段的值 */
INSERT INTO Persons (FirstName,LastName) VALUES ('Bill','Gates');
```

### SQL Server

```sql
CREATE TABLE Persons
(
P_Id int PRIMARY KEY IDENTITY,  /* 使用IDENTITY(20,10)更改起始值和递增值 */
LastName varchar(255) NOT NULL,
FirstName varchar(255),
Address varchar(255),
City varchar(255)
)
```

### Oracle

```sql
/* 使用序列（ sequence ）对象（该对象生成数字序列）创建自动增量（ auto-increment ）字段。 */
CREATE SEQUENCE seq_person
MINVALUE 1
START WITH 1
INCREMENT BY 1
CACHE 10

INSERT INTO Persons (ID,FirstName,LastName) VALUES (seq_person.nextval,'Lars','Monsen')
```

### Access

```sql
CREATE TABLE Persons
(
P_Id int PRIMARY KEY AUTOINCREMENT,  /* 使用AUTOINCREMENT(20,10)更改起始值和递增值 */
LastName varchar(255) NOT NULL,
FirstName varchar(255),
Address varchar(255),
City varchar(255)
)
```

## 索引

> **Tips:**
> 索引能够提高 SELECT 查询和 WHERE 子句的速度，但是却降低了包含 UPDATE 语句或 INSERT 语句的数据输入过程的速度。
> 创建单列索引还是聚簇索引，要看每次查询中，哪些列在作为过滤条件的 WHERE 子句中最常出现。
> 如果只需要一列，那么就应当创建单列索引。如果作为过滤条件的 WHERE 子句用到了两个或者更多的列，那么聚簇索引就是最好的选择。

CREATE INDEX index_name on table_name (column1, column2);

## 视图

预定义的 SQL 语句

```sql
CREATE VIEW CUSTOMERS_VIEW AS SELECT name, age FROM CUSTOMERS WHERE age IS NOT NULL [WITH CHECK OPTION];
CREATE OR REPLACE VIEW view_name AS SELECT column_name(s) FROM table_name WHERE condition;
DROP VIEW view_name;
```


# 存储过程

```sql
IF EXISTS (SELECT name FROM sysobjects WHERE name = 'Proc_InsertEmployee' AND type = 'P') 
DROP PROCEDURE Proc_InsertEmployee 
GO 
CREATE PROCEDURE Proc_InsertEmployee 
@PName nvarchar(50), 
@PSex nvarchar(4), 
@PAge int, 
@PWage money 
AS 
begin 
declare @PID nvarchar(50) 
select @PID=Max(员工编号) from tb_Employee 
if(@PID is null) 
set @PID='P1001' 
else 
set @PID='P'+cast(cast(substring(@PID,2,4) as int)+1 as nvarchar(50)) 
begin 
insert into tb_Employee values(@PID,@PName,@PSex,@PAge,@PWage) 
end 
end 
go

/* 带输出参数 */
CREATE PROC PROC_EXISTS 
( 
@UserName NVARCHAR(20), 
@PassWord NVARCHAR(20), 
@ReturnValue int OUTPUT 
) 
AS 
IF EXISTS(select * from tb_member where userName=@UserName AND passWord=@PassWord) 
set @ReturnValue= 100 
ELSE 
set @ReturnValue= -100 
GO

declare @IsRight int 
exec StuProc '赵雷' , @IsRight output
select @IsRight
```


> **Tips:** 需要使用精确的时间时，使用LONG代替DATE，精确到毫秒。
