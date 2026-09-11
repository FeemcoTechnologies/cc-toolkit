/**
 * @name Path traversal
 * @description File operations using user-controlled paths may be vulnerable to path traversal
 * @kind problem
 * @problem.severity error
 * @id python-path-traversal
 * @tags security
 */

import python

from Call c
where c.getFunc().(Name).getId() = "open"
select c, "open() call — ensure file path is not user-controlled"
