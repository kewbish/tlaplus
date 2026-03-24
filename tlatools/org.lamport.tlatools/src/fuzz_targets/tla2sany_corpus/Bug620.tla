---- MODULE TEST ----
Common(p(_)) == p(1)

Work == Common(LAMBDA a : a)       \* correct usage
THEOREM WorkT == Work!1!(1)        \* naming works

Break == Common(LAMBDA a, b : a+b) \* this would result in an error
THEOREM BreakT == Break!1!(1,2)    \* if this didn't crash the parser
====
