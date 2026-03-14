---- MODULE DetlefSpec ----
(*
--algorithm Spec {
      variable queue = << >> ;
      process (P \in Procs) 
      variable rV = null ; {
L1: while (TRUE) {
      either 
        with (v \in Val) {
           either { queue := queue \o <<v>> ;
                    rV := "okay" }
               or { queue := <<v>> \o  queue ;
                    rV := "okay"} 
               or rV := "full" ;
          }
      or { if (queue # << >>)
             { either { rV := Head(queue) ;
                        queue := Tail(queue) }
                   or { rV := queue[Len(queue)] ;
                        queue := [ i \in 1 .. (Len(queue) - 1) |-> queue[i]]}
             }
           else { rV := "empty" } 
         } ;
L2:   rV := null 
    } } }
*)
====
