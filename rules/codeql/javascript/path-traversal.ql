/**
 * @name Path traversal
 * @description File system operations using potentially user-controlled paths
 * @kind problem
 * @problem.severity error
 * @id javascript-path-traversal
 * @tags security
 */

import javascript

from CallExpr ce
where ce.getCalleeName() = "readFileSync" or
      ce.getCalleeName() = "writeFileSync" or
      ce.getCalleeName() = "readFile" or
      ce.getCalleeName() = "writeFile"
select ce, "File system operation — ensure path is not user-controlled"
