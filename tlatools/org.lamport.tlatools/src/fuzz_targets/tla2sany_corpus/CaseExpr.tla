---- MODULE CaseExpr ----
EXTENDS Naturals

F(x) == 
    CASE x = 0 -> 10
      [] x = 1 -> 20
      [] OTHER -> 30
====