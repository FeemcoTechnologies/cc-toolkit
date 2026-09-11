/**
 * @name XML external entity injection
 * @description XML parsing with external entity expansion enabled may leak sensitive data
 * @kind problem
 * @problem.severity error
 * @id go-xxe
 * @tags security
 */

import go

from CallExpr c
where c.getTarget().getName() = "Unmarshal" or
      c.getTarget().getName() = "Decode" or
      c.getTarget().getName() = "NewDecoder" or
      c.getTarget().getName() = "DecodeElement"
select c, "XML parsing — ensure external entity expansion is disabled to prevent XXE"
