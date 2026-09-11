/**
 * @name Unsafe deserialization
 * @description Java native deserialization of untrusted data may allow RCE
 * @kind problem
 * @problem.severity error
 * @id java-insecure-deserialization
 * @tags security
 */

import java

from NewClassExpr nce
where nce.getType().toString() = "ObjectInputStream"
select nce, "ObjectInputStream — ensure data is not user-controlled"
