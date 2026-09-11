/**
 * @name XML external entity (XXE) injection
 * @description XML parsing without disabling external entities may leak sensitive data
 * @kind problem
 * @problem.severity warning
 * @id java-xxe
 * @tags security
 */

import java

from NewClassExpr nce
where
  nce.getConstructor().getDeclaringType().hasQualifiedName("javax.xml.parsers", "DocumentBuilderFactory")
select nce, "XML parsing — ensure external entity processing is disabled"
