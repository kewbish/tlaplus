---- MODULE BadNewSymbMissingPieces ----
ASSUME /\ (\A NEW x \in : TRUE)
       /\ (\A VARIABLE : TRUE)
       /\ (\A STATE : TRUE)
====