---- MODULE EWD840MC2 ----
EXTENDS EWD840, TLC

const_123 == 4
===================

----- CONFIG EWD840MC2 -----
CONSTANT
N <- const_123
SPECIFICATION
Spec
PROPERTY
FalseLiveness2
====
