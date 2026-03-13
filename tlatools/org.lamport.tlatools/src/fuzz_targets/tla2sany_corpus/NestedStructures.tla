---- MODULE NestedStructures ----
EXTENDS Naturals

Data == [items |-> <<1, 2, 3>>, meta |-> [ok |-> TRUE, count |-> 3]]
Pred == \A x \in {1, 2, 3} : x \in DOMAIN [a |-> 1, b |-> 2, c |-> 3]
====