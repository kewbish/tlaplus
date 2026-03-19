---- MODULE NestedLetChoose ----
EXTENDS Naturals

Foo(x) ==
  LET y == x + 1
      z == CHOOSE n \in Nat : n = y
  IN z

Bar ==
  LET f[a \in {1, 2}] == a * a
  IN f[2]
====