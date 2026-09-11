/**
 * @name Insecure deserialization
 * @description Deserializing untrusted data can lead to remote code execution
 * @kind problem
 * @problem.severity error
 * @id javascript-insecure-deserialization
 * @tags security
 */

import javascript

from CallExpr ce
where
  ce.getCalleeName() = "unserialize" or
  ce.getCalleeName() = "deserialize"
select ce, "Insecure deserialization — avoid deserializing untrusted data"
