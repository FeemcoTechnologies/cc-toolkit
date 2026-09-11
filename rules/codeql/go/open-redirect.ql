/**
 * @name Open redirect
 * @description HTTP redirect target derived from user input may allow phishing
 * @kind problem
 * @problem.severity warning
 * @id go-open-redirect
 * @tags security
 */

import go

from CallExpr c
where c.getTarget().getName() = "Redirect" or
      c.getTarget().getName() = "RedirectHandler"
select c, "Redirect — ensure target URL is not user-controlled"
