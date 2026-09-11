/**
 * @name XML external entity (XXE) injection
 * @description XML parsing without disabling external entities may leak sensitive data
 * @kind problem
 * @problem.severity warning
 * @id python-xxe
 * @tags security
 */

import python

from Call c
where
  (
    c.getFunc().(Attribute).getObject().(Name).getId() = "xml" and
    c.getFunc().(Attribute).getName() in ["parse", "parsestring"]
  ) or
  (
    c.getFunc().(Attribute).getName() = "fromstring" and
    c.getFunc().(Attribute).getObject().(Name).getId() = "ET"
  )
select c, "XML parsing — consider disabling external entity resolution"
