/**
 * @name Path traversal
 * @description File operations using user-controlled paths may be vulnerable to path traversal
 * @kind problem
 * @problem.severity error
 * @id java-path-traversal
 * @tags security
 */

import java

from NewClassExpr nce
where
  nce.getConstructor().getDeclaringType().hasQualifiedName("java.io", "File")
select nce, "File constructor — ensure path is not user-controlled"
