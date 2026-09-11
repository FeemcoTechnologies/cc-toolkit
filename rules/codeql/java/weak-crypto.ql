/**
 * @name Weak cryptography
 * @description Use of weak cryptographic algorithms may be insecure
 * @kind problem
 * @problem.severity warning
 * @id java-weak-crypto
 * @tags security
 */

import java

from MethodAccess ma
where
  ma.getMethod().getName() = "getInstance" and
  ma.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "KeyGenerator") and
  ma.getArgument(0).(StringLiteral).getValue() in ["MD5", "SHA1", "DES", "RC4"]
select ma, "Weak cryptographic algorithm — use AES-256 or SHA-256"
