---- MODULE ProofStructured ----
EXTENDS Naturals

ASSUME 1 = 1

THEOREM AddZero ==
  \A n \in Nat : n + 0 = n
PROOF
  SUFFICES ASSUME NEW n \in Nat PROVE n + 0 = n
  HAVE n + 0 = n
  OBVIOUS
QED
====