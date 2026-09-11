/**
 * @name Missing Secure cookie flags
 * @description Cookies set without Secure or HttpOnly flags are exposed to theft
 * @kind problem
 * @problem.severity warning
 * @id go-insecure-cookie
 * @tags security
 */

import go

from CallExpr c
where c.getTarget().getName() = "SetCookie" or
      c.getTarget().getName() = "Set"
select c, "Cookie set — ensure Secure and HttpOnly flags are enabled"
