---- MODULE May09MC ----
EXTENDS May09, TLC

\* MV CONSTANT declarations@modelParameterConstants
CONSTANTS
a, b
----

\* MV CONSTANT definitions S
const_146183936175119000 == 
{a, b}
----

\* SYMMETRY definition
symm_146183936176120000 == 
Permutations(const_146183936175119000)
----

\* SPECIFICATION definition @modelBehaviorSpec:0
spec_146183936177121000 ==
Spec
----
\* PROPERTY definition @modelCorrectnessProperties:0
prop_146183936178122000 ==
[]<>(x=a) /\ []<>(x=b)
----
=============================================================================

----- CONFIG May09MC -----
\* MV CONSTANT declarations
CONSTANTS
a = a
b = b
\* MV CONSTANT definitions
CONSTANT
S <- const_146183936175119000
\* SYMMETRY definition
SYMMETRY symm_146183936176120000
\* SPECIFICATION definition
SPECIFICATION
spec_146183936177121000
\* PROPERTY definition
PROPERTY
prop_146183936178122000
====
