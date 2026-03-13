---- MODULE StateMachineStyle ----
EXTENDS Naturals

VARIABLE x, y

Init ==
    /\ x = 0
    /\ y = 1

StepA ==
    /\ x < 5
    /\ x' = x + 1
    /\ y' = y

StepB ==
    /\ y < 5
    /\ y' = y + 1
    /\ x' = x

Next == StepA \/ StepB

Spec == Init /\ [][Next]_<<x, y>>
====