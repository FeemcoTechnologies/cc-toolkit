/**
 * @name Weak cryptography
 * @description Use of weak cryptographic algorithms (MD5, SHA1) may be insecure
 * @kind problem
 * @problem.severity warning
 * @id python-weak-crypto
 * @tags security
 */

import python

from Expr e
where
  (
    e.(Attribute).getName() in ["md5", "sha1"] and
    e.(Attribute).getObject().(Name).getId() = "hashlib"
  ) or
  (
    e.(Name).getId() in ["md5", "sha1"]
  )
select e, "Weak cryptographic algorithm — use SHA-256 or stronger"
