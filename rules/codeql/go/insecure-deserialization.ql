/**
 * @name Insecure deserialization
 * @description Deserialization from untrusted sources may lead to RCE
 * @kind problem
 * @problem.severity error
 * @id go-insecure-deserialization
 * @tags security
 */

import go

from CallExpr c
where c.getTarget().getName() = "Unmarshal" or
      c.getTarget().getName() = "Decode" or
      c.getTarget().getName() = "NewDecoder" or
      c.getTarget().getName() = "Decrypt" or
      c.getTarget().getName() = "GobDecode"
select c, "Deserialization — ensure data source is trusted to prevent RCE"
