/**
 * @name Insecure deserialization
 * @description Deserializing untrusted data can lead to remote code execution
 * @kind problem
 * @problem.severity error
 * @id python-insecure-deserialization
 * @tags security
 */

import python

from Call c
where
  c.getFunc().(Attribute).getName() in ["loads", "load"] and
  c.getFunc().(Attribute).getObject().(Name).getId() in ["pickle", "cPickle", "yaml", "shelve"]
select c, "Insecure deserialization — avoid deserializing untrusted data"
