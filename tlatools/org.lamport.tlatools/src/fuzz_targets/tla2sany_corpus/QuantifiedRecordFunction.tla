---- MODULE QuantifiedRecordFunction ----
EXTENDS Naturals

Users == {"alice", "bob"}

Scores == [u \in Users |-> [midterm |-> 80, final |-> 90]]

Passed ==
    \A u \in Users :
        Scores[u].midterm >= 50 /\ Scores[u].final >= 50
====