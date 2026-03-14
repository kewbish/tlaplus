---- MODULE MC ----
EXTENDS TwoPhaseCommit, TLC

\* MV CONSTANT declarations@modelParameterConstants
CONSTANTS
anna, berta, charlie, dimitry, eugene
----

\* MV CONSTANT definitions Participant
const_146894168642461000 == 
{anna, berta, charlie, dimitry, eugene}
----

\* SYMMETRY definition
symm_146894168643562000 == 
Permutations(const_146894168642461000)
----

\* SPECIFICATION definition @modelBehaviorSpec:0
spec_146894168644663000 ==
Spec
----
\* INVARIANT definition @modelCorrectnessInvariants:0
inv_146894168645764000 ==
TypeOK
----
\* INVARIANT definition @modelCorrectnessInvariants:1
inv_146894168646965000 ==
CommitOrAbort
----
\* INVARIANT definition @modelCorrectnessInvariants:2
inv_146894168647966000 ==
AbortWins
----
\* PROPERTY definition @modelCorrectnessProperties:0
prop_146894168649067000 ==
Liveness
----
=============================================================================

----- CONFIG MC -----
\* MV CONSTANT declarations
CONSTANTS
anna = anna
berta = berta
charlie = charlie
dimitry = dimitry
eugene = eugene
\* MV CONSTANT definitions
CONSTANT
Participant <- const_146894168642461000
\* SYMMETRY definition
SYMMETRY symm_146894168643562000
\* SPECIFICATION definition
SPECIFICATION
spec_146894168644663000
\* INVARIANT definition
INVARIANT
inv_146894168645764000
inv_146894168646965000
inv_146894168647966000
\* PROPERTY definition
PROPERTY
prop_146894168649067000
====
