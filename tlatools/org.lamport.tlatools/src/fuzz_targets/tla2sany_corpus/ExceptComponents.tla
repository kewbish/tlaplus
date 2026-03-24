----- MODULE ExceptChained -----
VARIABLE a, b
Test == a' = [a EXCEPT ![b].a = FALSE]
====
