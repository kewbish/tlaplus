---- MODULE NewSymbInCluster ----
ASSUME /\ (\A NEW x \in {1, 2}: x = x)
       /\ (\A CONSTANT y \in {3, 4}: y = y)
       /\ (\A NEW CONSTANT z \in {5, 6}: z = z)
====