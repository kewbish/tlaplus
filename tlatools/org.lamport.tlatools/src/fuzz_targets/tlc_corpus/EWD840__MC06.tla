---- MODULE MC06 ----
EXTENDS EWD840, TLC

\* CONSTANT definitions @modelParameterConstants:0N
const_143073460396411000 == 
7
----

\* SPECIFICATION definition @modelBehaviorSpec:0
spec_143073460397412000 ==
Spec
----
\* PROPERTY definition @modelCorrectnessProperties:0
prop_143073460398413000 ==
Liveness
----
=============================================================================

----- CONFIG MC06 -----
\* CONSTANT definitions
CONSTANT
N <- const_143073460396411000
\* SPECIFICATION definition
SPECIFICATION
spec_143073460397412000
\* PROPERTY definition
PROPERTY
prop_143073460398413000
====
