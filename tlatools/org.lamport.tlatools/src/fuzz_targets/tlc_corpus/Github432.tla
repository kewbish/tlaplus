---- MODULE Github432 ----

EXTENDS TLC

CONSTANT Humans, Others

symmetry == Permutations(Humans) \union Permutations(Others)

VARIABLES set

TypeOK ==
    /\ set \subseteq Humans

Init ==
    /\ set = {}

Next ==
    \E h \in Humans:
        set' = set \union {h}

==================================

----- CONFIG Github432 -----
CONSTANT Humans = {%1%}
CONSTANT Others = {%2%}

INIT Init
NEXT Next
SYMMETRY symmetry
INVARIANT TypeOK
====
