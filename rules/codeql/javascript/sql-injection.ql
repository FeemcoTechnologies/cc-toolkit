/**
 * @name SQL injection
 * @description SQL queries built from untrusted input are vulnerable to injection
 * @kind problem
 * @problem.severity error
 * @id javascript-sql-injection
 * @tags security
 */

import javascript

from CallExpr ce
where
  ce.getCalleeName() = "query" or
  ce.getCalleeName() = "execute"
select ce, "SQL query execution — ensure arguments are not user-controlled"
