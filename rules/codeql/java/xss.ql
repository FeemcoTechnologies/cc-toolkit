/**
 * @name Cross-site scripting (XSS)
 * @description Writing unsanitized data to HTTP responses may lead to XSS
 * @kind problem
 * @problem.severity error
 * @id java-xss
 * @tags security
 */

import java

from MethodAccess ma
where
  ma.getMethod().getName() in ["write", "print", "println", "getWriter"] and
  ma.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse")
select ma, "Response output — ensure content is properly escaped"
