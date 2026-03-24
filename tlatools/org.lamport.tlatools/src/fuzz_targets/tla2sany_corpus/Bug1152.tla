---- MODULE Test ----
---- MODULE Inner ----
CONSTANT F(_, _)
====
op(x) == x
INSTANCE Inner WITH F <- op
====
