---- MODULE NewSymbVariableStateActionTemporal ----
ASSUME /\ (\A VARIABLE x: x = x)
       /\ (\A NEW VARIABLE y: y = y)
       /\ (\A STATE s: s = s)
       /\ (\A NEW STATE t: t = t)
       /\ (\A ACTION a: a = a)
       /\ (\A NEW ACTION b: b = b)
       /\ (\A TEMPORAL p: p = p)
       /\ (\A NEW TEMPORAL q: q = q)
====