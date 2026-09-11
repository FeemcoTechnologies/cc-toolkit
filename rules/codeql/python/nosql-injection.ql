/**
 * @name NoSQL injection
 * @description MongoDB queries using user-controlled input may be vulnerable to injection
 * @kind problem
 * @problem.severity error
 * @id python-nosql-injection
 * @tags security
 */

import python

from Call c
where
  c.getFunc().(Attribute).getName() in ["find", "find_one", "insert_one", "update_one", "delete_one", "aggregate"] and
  c.getFunc().(Attribute).getObject().(Attribute).getName() in ["collection", "db"]
select c, "NoSQL query — ensure query filters are not user-controlled"
