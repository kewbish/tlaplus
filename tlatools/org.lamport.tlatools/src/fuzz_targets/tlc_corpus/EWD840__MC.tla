---- MODULE MC ----
EXTENDS EWD840, TLC

\* CONSTANT definitions @modelParameterConstants:0N
const_143073460396411000 == 
10
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
\* Modification History
\* Created Mon May 04 12:16:43 CEST 2015 by markus

----- CONFIG MC -----
\* CONSTANT definitions
CONSTANT
N <- const_143073460396411000
\* SPECIFICATION definition
SPECIFICATION
spec_143073460397412000
\* PROPERTY definition
PROPERTY
prop_143073460398413000
\* Generated on Mon May 04 12:16:43 CEST 2015
====
