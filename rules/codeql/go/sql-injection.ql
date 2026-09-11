/**
 * @name SQL injection
 * @description SQL queries executed via database/sql may be vulnerable to injection
 * @kind problem
 * @problem.severity error
 * @id go-sql-injection
 * @tags security
 */

import go

from CallExpr c
where c.getTarget().getName() = "Query" or
      c.getTarget().getName() = "QueryRow" or
      c.getTarget().getName() = "Exec" or
      c.getTarget().getName() = "Prepare"
select c, "SQL query — ensure arguments are not built from user input"
