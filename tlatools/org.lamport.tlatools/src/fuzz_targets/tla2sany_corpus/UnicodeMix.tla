---- MODULE UnicodeMix ----
EXTENDS Naturals

A == 1 \in {1, 2, 3}
B == \A x \in {1,2,3} : x \geq 1
C == \E y \in {1,2,3} : y \leq 3
====