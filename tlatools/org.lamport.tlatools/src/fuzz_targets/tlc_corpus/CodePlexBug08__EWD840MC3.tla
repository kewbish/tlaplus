---- MODULE EWD840MC3 ----
EXTENDS EWD840, TLC

const_123 == 4
===================

----- CONFIG EWD840MC3 -----
CONSTANT
N <- const_123
SPECIFICATION
Spec2
PROPERTY
FalseLiveness3
====
