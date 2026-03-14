---- MODULE EWD840MC4 ----
EXTENDS EWD840, TLC

const_123 == 4
===================

----- CONFIG EWD840MC4 -----
CONSTANT
N <- const_123
SPECIFICATION
Spec
PROPERTY
AllNodesTerminateIfNoMessages
====
