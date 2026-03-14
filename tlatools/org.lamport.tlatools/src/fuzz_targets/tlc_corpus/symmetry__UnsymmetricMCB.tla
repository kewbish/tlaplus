---- MODULE UnsymmetricMCB ----
EXTENDS Unsymmetric, TLC

\* MV CONSTANT declarations@modelParameterConstants
CONSTANTS
a, b
----

\* MV CONSTANT definitions S
const_1444366015085101000 == 
{a, b}
----

\* SYMMETRY definition
symm_1444366015096102000 == 
Permutations(const_1444366015085101000)
----

\* SPECIFICATION definition @modelBehaviorSpec:0
spec_1444366015106103000 ==
SpecB
----
\* PROPERTY definition @modelCorrectnessProperties:0
prop_1444366015116104000 ==
Prop
----
=============================================================================

----- CONFIG UnsymmetricMCB -----
\* MV CONSTANT declarations
CONSTANTS
a = a
b = b
\* MV CONSTANT definitions
CONSTANT
S <- const_1444366015085101000
\* SYMMETRY definition
SYMMETRY symm_1444366015096102000
\* SPECIFICATION definition
SPECIFICATION
spec_1444366015106103000
\* PROPERTY definition
PROPERTY
prop_1444366015116104000
====
