---- MODULE Test ----
---- MODULE Inner ----
x !! y == TRUE
====
M == INSTANCE Inner
op == M!!!(1, 2)
====
