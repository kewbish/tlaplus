---- MODULE LogicalOperators ----
EXTENDS Naturals

P(x) == (x > 0) /\ (x < 10)
Q(x) == (x = 3) \/ (x = 5)
R(x) == P(x) => Q(x)
====