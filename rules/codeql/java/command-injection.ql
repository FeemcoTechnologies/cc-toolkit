/**
 * @name Command injection
 * @description Runtime exec() with untrusted input may lead to command injection
 * @kind problem
 * @problem.severity error
 * @id java-command-injection
 * @tags security
 */

import java

from MethodAccess ma
where
  ma.getMethod().getName() = "exec" and
  ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime")
select ma, "Command execution — ensure arguments are not user-controlled"
