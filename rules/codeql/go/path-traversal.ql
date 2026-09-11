/**
 * @name Path traversal
 * @description File operations with user-controlled paths may allow path traversal
 * @kind problem
 * @problem.severity error
 * @id go-path-traversal
 * @tags security
 */

import go

from CallExpr c
where c.getTarget().getName() = "Open" or
      c.getTarget().getName() = "OpenFile" or
      c.getTarget().getName() = "Create" or
      c.getTarget().getName() = "ReadFile" or
      c.getTarget().getName() = "WriteFile" or
      c.getTarget().getName() = "ReadDir"
select c, "File I/O — validate and sanitize file paths to prevent traversal"
