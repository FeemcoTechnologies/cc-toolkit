/**
 * @name Command injection
 * @description Shell commands executed via child_process may be vulnerable to injection
 * @kind problem
 * @problem.severity error
 * @id javascript-command-injection
 * @tags security
 */

import javascript

from CallExpr ce
where
  ce.getCalleeName() in ["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"]
select ce, "Shell command execution — ensure arguments are not user-controlled"
