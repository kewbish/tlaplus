---- MODULE OneBitMutexMC ----
EXTENDS OneBitMutex, TLC

\* MV CONSTANT declarations@modelParameterConstants
CONSTANTS
A, B
----

\* MV CONSTANT definitions Procs
const_144491423291817000 == 
{A, B}
----

\* SYMMETRY definition
symm_144481269487927000 == 
Permutations(const_144491423291817000)
----

\* SPECIFICATION definition @modelBehaviorSpec:0
spec_144491423292818000 ==
Spec
----
\* PROPERTY definition @modelCorrectnessProperties:0
prop_144491423293819000 ==
StarvationFreedom
----
=============================================================================

----- CONFIG OneBitMutexMC -----
\* MV CONSTANT declarations
CONSTANTS
A = A
B = B
\* MV CONSTANT definitions
CONSTANT
Procs <- const_144491423291817000
\* SYMMETRY definition
SYMMETRY symm_144481269487927000
\* SPECIFICATION definition
SPECIFICATION
spec_144491423292818000
\* PROPERTY definition
PROPERTY
prop_144491423293819000
====
