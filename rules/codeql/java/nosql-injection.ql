/**
 * @name NoSQL injection
 * @description MongoDB queries built with user input may allow injection
 * @kind problem
 * @problem.severity error
 * @id java-nosql-injection
 * @tags security
 */

import java

from MethodAccess ma
where ma.getMethod().getName() in ["find", "findOne", "insert", "update", "aggregate"] and
      ma.getQualifier().(ClassInstanceExpr).getType().toString().matches("%BasicDBObject%") or
      ma.getQualifier().(ClassInstanceExpr).getType().toString().matches("%Document%")
select ma, "NoSQL query — ensure filters are not built from user input"
