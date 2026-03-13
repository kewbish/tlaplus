---- MODULE TemporalWithAction ----
EXTENDS Naturals

VARIABLE x

Init == x = 0

Advance ==
    /\ x < 3
    /\ x' = x + 1

Stutter ==
    /\ x' = x

Next == Advance \/ Stutter

Spec == Init /\ [][Next]_x /\ <> (x = 3)
====