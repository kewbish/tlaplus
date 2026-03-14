---- MODULE MC ----
EXTENDS NQSpecImpliesQSpec, TLC

\* MV CONSTANT declarations@modelParameterConstants
CONSTANTS
e1
----

\* MV CONSTANT declarations@modelParameterConstants
CONSTANTS
id1
----

\* MV CONSTANT declarations@modelParameterConstants
CONSTANTS
d1
----

\* MV CONSTANT declarations@modelParameterConstants
CONSTANTS
v1
----

\* MV CONSTANT definitions EnQers
const_14476073153412000 == 
{e1}
----

\* MV CONSTANT definitions Ids
const_14476073153513000 == 
{id1}
----

\* MV CONSTANT definitions DeQers
const_14476073153614000 == 
{d1}
----

\* MV CONSTANT definitions Data
const_14476073153715000 == 
{v1}
----

\* CONSTANT definitions @modelParameterConstants:4InitData
const_14476073153816000 == 
v1
----

\* SPECIFICATION definition @modelBehaviorSpec:0
spec_144760731543311000 ==
SpecI
----
\* INVARIANT definition @modelCorrectnessInvariants:0
inv_144760731544312000 ==
TypeOKI
----
\* PROPERTY definition @modelCorrectnessProperties:0
prop_144760731545313000 ==
I!Spec
----
=============================================================================
\* Modification History
\* Created Sun Nov 15 18:08:35 CET 2015 by markus

----- CONFIG MC -----
\* MV CONSTANT declarations
CONSTANTS
e1 = e1
\* MV CONSTANT declarations
CONSTANTS
id1 = id1
\* MV CONSTANT declarations
CONSTANTS
d1 = d1
\* MV CONSTANT declarations
CONSTANTS
v1 = v1
\* MV CONSTANT definitions
CONSTANT
EnQers <- const_14476073153412000
\* MV CONSTANT definitions
CONSTANT
Ids <- const_14476073153513000
\* MV CONSTANT definitions
CONSTANT
DeQers <- const_14476073153614000
\* MV CONSTANT definitions
CONSTANT
Data <- const_14476073153715000
\* CONSTANT declarations
CONSTANT Busy = Busy
\* CONSTANT declarations
CONSTANT NoData = NoData
\* CONSTANT definitions
CONSTANT
InitData <- const_14476073153816000
\* CONSTANT definition
CONSTANT
Done = Done
NotAnId = NotAnId
NotAnElement = NotAnElement
top = top
\* SPECIFICATION definition
SPECIFICATION
spec_144760731543311000
\* INVARIANT definition
INVARIANT
inv_144760731544312000
\* PROPERTY definition
PROPERTY
prop_144760731545313000
\* Generated on Sun Nov 15 18:08:35 CET 2015
====
