/**
 * @name Log injection
 * @description Sensitive or untrusted data written to logs may enable injection or leakage
 * @kind problem
 * @problem.severity warning
 * @id javascript-log-injection
 * @tags security
 */

import javascript

from CallExpr ce
where ce.getCalleeName() in ["log", "info", "warn", "error", "debug"]
select ce, "Log write — ensure sensitive data is redacted and input is escaped"
