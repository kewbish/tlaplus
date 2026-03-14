---------------------------- MODULE Github746 ----------------------------

VARIABLE i

Init == i = 1

Next == UNCHANGED i

Spec == Init /\ [][Next]_i

Inv == i = 2

Alias == [
i |-> i, foo |-> "bar", j |-> i = i'
]

==========================================================================

----- CONFIG Github746 -----
SPECIFICATION Spec
INVARIANTS Inv
ALIAS Alias
====
