---- MODULE April21MC ----
EXTENDS April21, TLC

\* MV CONSTANT declarations@modelParameterConstants
CONSTANTS
m1, m2
----

\* MV CONSTANT definitions S
const_146115895642519000 == 
{m1, m2}
----

\* SYMMETRY definition
symm_146115895643520000 == 
Permutations(const_146115895642519000)
----

\* SPECIFICATION definition @modelBehaviorSpec:0
spec_146115895644521000 ==
Spec
----
\* PROPERTY definition @modelCorrectnessProperties:0
prop_146115895645522000 ==
Live
----
=============================================================================

----- CONFIG April21MC -----
\* MV CONSTANT declarations
CONSTANTS
m1 = m1
m2 = m2
\* MV CONSTANT definitions
CONSTANT
S <- const_146115895642519000
\* SYMMETRY definition
SYMMETRY symm_146115895643520000
\* SPECIFICATION definition
SPECIFICATION
spec_146115895644521000
\* PROPERTY definition
PROPERTY
prop_146115895645522000
====
