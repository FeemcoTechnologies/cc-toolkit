/**
 * @name SQL injection
 * @description SQL queries executed via Statement/PreparedStatement may be vulnerable to injection
 * @kind problem
 * @problem.severity error
 * @id java-sql-injection
 * @tags security
 */

import java

from MethodAccess ma
where ma.getMethod().getName() = "executeQuery" or
      ma.getMethod().getName() = "executeUpdate" or
      ma.getMethod().getName() = "execute"
select ma, "SQL execution — ensure query is not built from user input"
