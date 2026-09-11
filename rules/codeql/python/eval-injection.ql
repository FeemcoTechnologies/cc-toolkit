/**
 * @name Code injection (eval/exec)
 * @description Dynamic code execution with potentially untrusted input
 * @kind problem
 * @problem.severity error
 * @id python-eval-injection
 * @tags security
 */

import python

from Call c
where
  c.getFunc().(Name).getId() in ["eval", "exec", "compile"]
select c, "Dynamic code execution — avoid using eval/exec with untrusted input"
