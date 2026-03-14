---- MODULE MC ----
EXTENDS PrintTraceRace, TLC

\* INIT definition @modelBehaviorInit:0
init_143958263805435000 ==
TestInit
----
\* NEXT definition @modelBehaviorNext:0
next_143958263806436000 ==
TestNext
----
\* INVARIANT definition @modelCorrectnessInvariants:0
inv_143958263807437000 ==
TestTypeInv
----
=============================================================================

----- CONFIG MC -----
\* INIT definition
INIT
init_143958263805435000
\* NEXT definition
NEXT
next_143958263806436000
\* INVARIANT definition
INVARIANT
inv_143958263807437000
\* Generated on Fri Aug 14 13:03:58 PDT 2015
====
