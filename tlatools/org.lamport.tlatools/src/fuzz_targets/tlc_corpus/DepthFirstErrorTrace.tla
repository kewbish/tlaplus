--------------------------- MODULE DepthFirstErrorTrace ---------------------------
EXTENDS Integers

VARIABLES x

Spec == (x=0) /\ [][x'=x+1]_<<x>>

Inv == x < 7
=============================================================================

----- CONFIG DepthFirstErrorTrace -----
SPECIFICATION
Spec
INVARIANT
Inv
====
