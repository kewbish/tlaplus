---- MODULE ConstantOperatorConfiguration ----

CONSTANT F(_)
VARIABLE x

Init == x = 0
Next == x' = F(x)
Inv == x /= 2

====

----- CONFIG ConstantOperatorConfiguration -----
INIT Init
NEXT Next

CONSTANT
    F(0) = 1
    F(1) = 2
    F(2) = 2

INVARIANT Inv
====
