/**
 * @name Cross-site scripting (XSS)
 * @description Content rendered without escaping may be vulnerable to XSS
 * @kind problem
 * @problem.severity error
 * @id python-xss
 * @tags security
 */

import python

from Call c
where
  (
    c.getFunc().(Attribute).getName() = "Markup" and
    c.getFunc().(Attribute).getObject().(Name).getId() = "markupsafe"
  ) or
  (
    c.getFunc().(Attribute).getName() = "mark_safe"
  ) or
  (
    c.getFunc().(Attribute).getName() = "render_template_string"
  )
select c, "Potentially unsafe HTML rendering — ensure content is escaped"
