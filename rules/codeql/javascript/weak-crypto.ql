/**
 * @name Weak cryptography
 * @description Use of weak cryptographic algorithms may be insecure
 * @kind problem
 * @problem.severity warning
 * @id javascript-weak-crypto
 * @tags security
 */

import javascript

from CallExpr ce
where
  ce.getCalleeName() in ["createHash", "createHmac"] and
  ce.getArgument(0).(StringLiteral).getValue() in ["md5", "sha1"]
select ce, "Weak cryptographic algorithm — use SHA-256 or stronger"
