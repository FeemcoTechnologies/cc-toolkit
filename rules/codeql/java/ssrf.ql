/**
 * @name Server-side request forgery (SSRF)
 * @description Outbound HTTP connections with potentially user-controlled URLs
 * @kind problem
 * @problem.severity warning
 * @id java-ssrf
 * @tags security
 */

import java

from MethodAccess ma
where
  ma.getMethod().getName() in ["openConnection", "openStream", "send", "execute"]
select ma, "HTTP connection — ensure URL is not user-controlled"
