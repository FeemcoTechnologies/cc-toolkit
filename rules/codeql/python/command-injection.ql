/**
 * @name Command injection
 * @description Commands built with os.system, subprocess.run/Popen, etc. may be vulnerable to injection if arguments are user-controlled
 * @kind problem
 * @problem.severity error
 * @id python-command-injection
 * @tags security
 */

import python

from Call c
where c.getFunc().(Attribute).getName() in ["system", "popen", "run", "Popen"]
select c, "Shell command call — ensure arguments are not user-controlled"
