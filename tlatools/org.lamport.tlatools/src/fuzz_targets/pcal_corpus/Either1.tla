---- MODULE Either1 ----
(*
--algorithm Either
      variables x = 0 ; y = 0 ;
      begin a: either x := 1 ; b: x := x + 1;
                   or y := 1 ; c: y := y + 1;
               end either ;
            d: assert x+y = 2 ;
     end algorithm
*)
====
