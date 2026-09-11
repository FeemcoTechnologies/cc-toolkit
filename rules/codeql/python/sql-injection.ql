/**
 * @name SQL injection
 * @description Calls to execute() with a string argument may be vulnerable to SQL injection if the argument is user-controlled
 * @kind problem
 * @problem.severity error
 * @id python-sql-injection
 * @tags security
 */

import python

from Call c
where c.getFunc().(Attribute).getName() = "execute"
select c, "SQL execute() call — ensure argument is not user-controlled"
