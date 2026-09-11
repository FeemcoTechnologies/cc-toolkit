/**
 * @name Server-side request forgery
 * @description HTTP requests with user-controlled URLs may enable SSRF
 * @kind problem
 * @problem.severity error
 * @id go-ssrf
 * @tags security
 */

import go

from CallExpr c
where c.getTarget().getName() = "Get" or
      c.getTarget().getName() = "Post" or
      c.getTarget().getName() = "Do" or
      c.getTarget().getName() = "NewRequest"
select c, "HTTP request — ensure target URL is not user-controlled to prevent SSRF"
