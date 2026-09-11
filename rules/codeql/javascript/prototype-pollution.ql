/**
 * @name Prototype pollution
 * @description Merging untrusted objects can pollute Object.prototype
 * @kind problem
 * @problem.severity warning
 * @id javascript-prototype-pollution
 * @tags security
 */

import javascript

from CallExpr ce
where
  ce.getCalleeName() in ["assign", "merge", "extend"]
select ce, "Object merge/assign — ensure __proto__ key is not user-controlled"
