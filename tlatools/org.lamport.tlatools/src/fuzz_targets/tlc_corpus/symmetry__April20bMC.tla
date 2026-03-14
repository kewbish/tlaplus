---- MODULE April20bMC ----
EXTENDS April20b, TLC

\* MV CONSTANT declarations@modelParameterConstants
CONSTANTS
m1, m2
----

\* MV CONSTANT definitions S
const_146115906599338000 == 
{m1, m2}
----

\* SYMMETRY definition
symm_146115906600339000 == 
Permutations(const_146115906599338000)
----

\* SPECIFICATION definition @modelBehaviorSpec:0
spec_146115906601340000 ==
Spec
----
\* PROPERTY definition @modelCorrectnessProperties:0
prop_146115906602341000 ==
Live
----
=============================================================================

----- CONFIG April20bMC -----
\* MV CONSTANT declarations
CONSTANTS
m1 = m1
m2 = m2
\* MV CONSTANT definitions
CONSTANT
S <- const_146115906599338000
\* SYMMETRY definition
SYMMETRY symm_146115906600339000
\* SPECIFICATION definition
SPECIFICATION
spec_146115906601340000
\* PROPERTY definition
PROPERTY
prop_146115906602341000
====
