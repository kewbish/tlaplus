---------- MODULE Test2 -----------

(* This spec originates from an email conversation between Leslie and Yuan in 2009 *)

EXTENDS Naturals, TLC
VARIABLE x
ASSUME TLCSet(42, 0)
Init == x=0

Next == x' = (x+1)%5 /\ TLCSet(42, TLCGet(42)+1)

Spec == Init /\ [][Next]_x /\ WF_x(Next)

Prop1 == []<>(x=1)

PostCondition ==
    PrintT(TLCGet(42)) /\ TLCGet(42) \in {1050,2000}

PostConditionViolated ==
    TLCGet(42) = 0

==============================================

----- CONFIG Test2 -----
\* SPECIFICATION definition
SPECIFICATION
Spec
\* PROPERTY definition
PROPERTY
Prop1
POSTCONDITION
PostCondition
\* Generated on Wed Mar 25 21:34:22 CET 2015
====
