/**
 * @name Cross-site scripting (XSS)
 * @description Assignment to innerHTML with potentially user-controlled data
 * @kind problem
 * @problem.severity error
 * @id javascript-xss
 * @tags security
 */

import javascript

from AssignExpr ae
where ae.getLhs().(PropAccess).getPropertyName() = "innerHTML"
select ae, "innerHTML assignment — ensure right-hand side is sanitized"
