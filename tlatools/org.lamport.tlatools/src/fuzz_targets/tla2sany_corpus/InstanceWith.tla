---- MODULE InstanceWith ----
EXTENDS Naturals

Inner(a, b) == a + b

M == INSTANCE Naturals

N == INSTANCE Naturals WITH Nat <- {0, 1, 2}

Value == Inner(1, 2)
====