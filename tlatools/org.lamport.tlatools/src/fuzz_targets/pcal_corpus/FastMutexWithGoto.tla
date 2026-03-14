---- MODULE FastMutexWithGoto ----
(*
--algorithm FastMutex
variables x = 0 ; y = 0 ; b = [i \in 1..N |-> FALSE] ; 

process Proc \in 1..N
  variables j = 0 ; 
  begin
    ncs: while TRUE do 
              skip ;  \* Noncritical section.
       start: b[self] := TRUE ;
          l1: x := self ;
          l2: if y # 0
                then l3: b[self] := FALSE ;
                     l4: when y = 0 ; 
                          goto start ;
              end if ;
          l5: y := self ;
          l6: if x # self 
                then l7: b[self] := FALSE ;
                         j := 1 ;
                     l8: while j \leq N do 
                           when ~b[j] ;
                           j := j+1 ;
                         end while ;
                     l9: if y # self then l10: when y = 0 ;
                         goto start ;
                           end if ;
               end if;
          cs: skip ; \* the critical section
         l11: y := 0 ;
         l12: b[self] := FALSE ;
         end while ;
end process

end algorithm

**********************
*)
====
