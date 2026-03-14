---- MODULE MC03Sim ----
EXTENDS EWD840, TLC, Sequences

Level ==
    TLCGet("level") < 15

ActionConstraint ==
    vars' # vars
=============================================================================

----- CONFIG MC03Sim -----
CONSTANT
    N = 5
SPECIFICATION
    Spec
ACTION_CONSTRAINT
    ActionConstraint
\* INVARIANT
\*     Level
====
