/**
 * @name Log injection
 * @description Sensitive or untrusted data written to logs may enable injection or leakage
 * @kind problem
 * @problem.severity warning
 * @id go-log-injection
 * @tags security
 */

import go

from CallExpr c
where c.getTarget().getName() in ["Printf", "Println", "Fatalf", "Info", "Error",
                                  "Warn", "Debug", "Infof", "Errorf", "Warnf", "Debugf"]
select c, "Log write — ensure sensitive data is redacted and input is escaped"
