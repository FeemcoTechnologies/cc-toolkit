/**
 * @name Insecure cookie
 * @description Cookies set without Secure or HttpOnly flags are exposed to theft
 * @kind problem
 * @problem.severity warning
 * @id javascript-insecure-cookie
 * @tags security
 */

import javascript

from CallExpr ce
where ce.getCalleeName() = "cookie" or
      ce.getCalleeName() = "setHeader" or
      ce.getCalleeName() = "create" or
      ce.getCalleeName() = "signedCookie"
select ce, "Cookie set — ensure Secure and HttpOnly flags are enabled"
