---- MODULE SubSub ----
(*
--algorithm SubSub
  process proc \in 1..3
   variables x = [i \in {"a", "b"} |-> 0] ,
             y = [i \in 5..6 |-> "a"] ,
             z
   begin
     lab : z := 5 ;
           y[z] := "b" ;
           x[y[z]] := 1 ;
           assert x[y[z]] = 1 ;
           assert y[z] = "b"
   end process

end algorithm
****
*)
====
