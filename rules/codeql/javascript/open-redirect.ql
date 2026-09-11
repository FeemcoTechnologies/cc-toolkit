/**
 * @name Open redirect
 * @description HTTP redirect target derived from user input may allow phishing
 * @kind problem
 * @problem.severity warning
 * @id javascript-open-redirect
 * @tags security
 */

import javascript

from CallExpr ce
where ce.getCalleeName() in ["redirect", "res.redirect", "location.assign",
                             "window.location.replace", "setHeader"]
select ce, "Redirect — ensure target URL is not user-controlled"
