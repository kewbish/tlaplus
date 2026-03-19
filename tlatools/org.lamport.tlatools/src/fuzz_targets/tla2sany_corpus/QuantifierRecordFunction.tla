---- MODULE QuantifierRecordFunction ----
EXTENDS Naturals, Sequences

R == [a |-> 1, b |-> 2]

F == [x \in {1,2,3} |-> x * x]

S == {x \in {1,2,3,4} : x % 2 = 0}

P == \A x \in DOMAIN F : F[x] \in Nat

Q == \E r \in {R} : r.a = 1
====