---- MODULE LocalOperatorAndSet ----
EXTENDS Naturals

Double(x) == x * 2
Good == {x \in 1..10 : Double(x) >= 8}

Check ==
    \E x \in Good :
        x = 4
====