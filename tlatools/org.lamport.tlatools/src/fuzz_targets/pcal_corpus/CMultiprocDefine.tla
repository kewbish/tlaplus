---- MODULE CMultiprocDefine ----
(*
--algorithm MultiprocDefine {
  variables n = 0 ;
  define { nplus1 == n + 1 
           nplus2 == nplus1 + 1 } ;
  process (Proc \in {1, 2, 3})
    variables i ;
    { main : i := nplus2 ;
             assert i = 2 ;
    } }
*)
====
