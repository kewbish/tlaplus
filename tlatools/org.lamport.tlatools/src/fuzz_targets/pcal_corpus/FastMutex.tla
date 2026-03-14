---- MODULE FastMutex ----
(*
--algorithm FastMutex
  variables x ; y = 0 ; b = [i \in 1..N |-> FALSE] ; 
process Proc \in 1..N
variables j = 0 ; failed = FALSE ;
begin
start : while TRUE
         do l1 : b[self] := TRUE ;
            l2 : x := self ;
            l3 : if y # 0
                   then l4 : b[self] := FALSE ;
                        l5 : when y = 0 ; skip ;
                   else l6 : y := self ;
                        l7 : if x # self 
                               then l8 : b[self] := FALSE ;
                                         j := 1 ;
                                    l9 : while (j \leq N)
                                           do when ~b[j] ;
                                              j := j+1 ;
                                         end while ;
                                    l10 : if y # self
                                            then when y = 0 ;
                                                 failed := TRUE ;
                                          end if;
                             end if ;
                        cs : if ~ failed
                               then       skip ; \* the critical section
                                    l11 : y := 0 ;
                                    l12 : b[self] := FALSE ;
                               else failed := FALSE ;
                             end if ;
                  end if ;
        end while ;
end process
end algorithm

**********************
*)
====
