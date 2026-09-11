/**
 * @name NoSQL injection
 * @description MongoDB queries built with user input may allow injection
 * @kind problem
 * @problem.severity error
 * @id go-nosql-injection
 * @tags security
 */

import go

from CallExpr c
where c.getTarget().getName() in ["Find", "FindOne", "InsertOne", "UpdateOne", "Aggregate"]
select c, "NoSQL query — ensure filters are not built from user input"
