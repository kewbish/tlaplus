---- MODULE pf_pick ----
THEOREM \E x \in {1}: x = x
PROOF
  <1>1. PICK x \in {1}: x = x
  <1>2. x = x
    OBVIOUS
  <1>q. QED
    OBVIOUS
====