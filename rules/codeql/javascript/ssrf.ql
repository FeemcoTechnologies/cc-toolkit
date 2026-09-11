/**
 * @name Server-side request forgery (SSRF)
 * @description Outbound HTTP requests with potentially user-controlled URLs
 * @kind problem
 * @problem.severity warning
 * @id javascript-ssrf
 * @tags security
 */

import javascript

from CallExpr ce
where
  ce.getCalleeName() in ["fetch", "got", "axios", "request"]
select ce, "HTTP request — ensure URL is not user-controlled"
