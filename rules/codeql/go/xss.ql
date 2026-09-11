/**
 * @name Cross-site scripting
 * @description Unsanitized data written to HTTP response may cause XSS
 * @kind problem
 * @problem.severity error
 * @id go-xss
 * @tags security
 */

import go

from CallExpr c
where c.getTarget().getName() = "Write" or
      c.getTarget().getName() = "WriteString" or
      c.getTarget().getName() = "Writef" or
      c.getTarget().getName() = "Fprint" or
      c.getTarget().getName() = "Fprintf"
select c, "HTTP response write — ensure output is HTML-escaped to prevent XSS"
