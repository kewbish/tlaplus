--------------------------- MODULE MinimumDiameter ---------------------------
VARIABLES x

Spec == (x = 0) /\ [][UNCHANGED x]_x
=============================================================================

----- CONFIG MinimumDiameter -----
SPECIFICATION
Spec
====
