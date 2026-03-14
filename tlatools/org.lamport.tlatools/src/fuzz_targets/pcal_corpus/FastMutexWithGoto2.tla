---- MODULE FastMutexWithGoto2 ----
(*
--algorithm FastMutex
  variables x = 0 ; y = 0 ; b = [i \in 1..N |-> FALSE] ; 
process Proc \in 1..N
variables S = {} ; 
begin
start : while TRUE
         do l1 : b[self] := TRUE ;
            l2 : x := self ;
            l3 : if y # 0
                   then l4 : b[self] := FALSE ;
                        l5 : when y = 0 ; 
                             goto start ;
                 end if ;
            l6 : y := self ;
            l7 : if x # self 
                   then l8 : b[self] := FALSE ;
                             S := 1..N \ {self} ;
                        l9 : while S # {} do
                              with j \in S do when ~b[j] ;
                                     S := S \ {j}
                              end with ;
                             end while ;
                       l10 : if y # self then l11 : when y = 0 ;
                                                    goto start ;
                             end if ;
                 end if;
             cs : skip ; \* the critical section
            l12 : y := 0 ;
            l13 : b[self] := FALSE ;
        end while ;
end process
end algorithm

**********************
*)
====
