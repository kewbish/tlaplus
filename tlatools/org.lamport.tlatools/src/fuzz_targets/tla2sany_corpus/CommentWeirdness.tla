(*
  ---- MODULE Fake ----
  This is only a comment.
  VARIABLE y

  (*
    nested-like comment (not really allowed)
  *)
*)

---- MODULE CommentWeirdness ----
\* comment immediately after header
EXTENDS Naturals

(*
  Another block comment with symbols:
  \A \E => <= >=
*)

X == 1

\* suspicious content: ---- MODULE Shadow ----

Y == X + 1

\* trailing weirdness ---- MODULE End
====