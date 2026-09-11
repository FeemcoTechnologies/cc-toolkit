/**
 * @name Command injection
 * @description os/exec.Command with untrusted input may lead to command injection
 * @kind problem
 * @problem.severity error
 * @id go-command-injection
 * @tags security
 */

import go

from CallExpr c
where c.getTarget().getName() = "Command" or
      c.getTarget().getName() = "CommandContext" or
      c.getTarget().getName() = "StartProcess"
select c, "Command execution — ensure arguments are not user-controlled"
