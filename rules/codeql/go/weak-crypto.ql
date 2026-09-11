/**
 * @name Weak cryptography
 * @description Use of weak cryptographic algorithms (MD5, SHA1, DES, RC4)
 * @kind problem
 * @problem.severity error
 * @id go-weak-crypto
 * @tags security
 */

import go

from Function f
where f.hasQualifiedName("crypto/md5", "New") or
      f.hasQualifiedName("crypto/sha1", "New") or
      f.hasQualifiedName("crypto/des", "NewDESCipher") or
      f.hasQualifiedName("crypto/rc4", "NewCipher")
select f, "Use of weak cryptographic algorithm — prefer SHA-256 or AES"
