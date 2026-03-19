---- MODULE ProofByObvious ----
EXTENDS Naturals

THEOREM Trivial ==
  0 = 0
PROOF
  OBVIOUS
QED

THEOREM AlsoTrivial ==
  1 = 1
BY OBVIOUS
====