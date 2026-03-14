---- MODULE Either3 ----
(*
--algorithm Either
      variables x = 0 ; y = 0 ; z = 0 ;
      begin a: either    x := 1 ; 
                      b: x := x + 1; 
                   or y := 1 ; c: y := y + 1;
                   or z := 100
               end either ;
            d: either when x = 0 ; z := z + 1 ;
                   or when x = 2 ; z := z + 3 ;
               end either ;     
               assert (x+y = 2) \/ ((z = 101) /\ (x+y=0));
               assert (z < 100) => (z = x + 1) ;
     end algorithm
*)
====
