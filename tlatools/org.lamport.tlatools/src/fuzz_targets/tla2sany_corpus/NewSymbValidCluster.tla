---- MODULE NewSymbValidCluster ----
ASSUME /\ (\A NEW x: x = x)
       /\ (\A CONSTANT y: y = y)
       /\ (\A NEW CONSTANT z: z = z)
====