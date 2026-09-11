/**
 * @name NoSQL injection
 * @description MongoDB queries built with user input may allow injection
 * @kind problem
 * @problem.severity error
 * @id javascript-nosql-injection
 * @tags security
 */

import javascript

from CallExpr ce
where ce.getCalleeName() in ["find", "findOne", "findOneAndUpdate", "insertOne",
                             "updateOne", "aggregate"]
select ce, "NoSQL query — ensure filters are not built from user input"
