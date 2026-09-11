/**
 * @name Server-side request forgery (SSRF)
 * @description Outbound HTTP requests with potentially user-controlled URLs
 * @kind problem
 * @problem.severity warning
 * @id python-ssrf
 * @tags security
 */

import python

from Call c
where
  c.getFunc().(Attribute).getName() = "urlopen" or
  (
    c.getFunc().(Attribute).getObject().(Name).getId() in ["requests", "httpx"] and
    c.getFunc().(Attribute).getName() in ["get", "post", "put", "delete", "patch", "request"]
  )
select c, "HTTP request — ensure URL is not user-controlled"
