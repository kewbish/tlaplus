---- MODULE FastMutex2 ----
(*
--algorithm FastMutex
  variables x = 0 ; y = 0 ; b = [i \in 1..N |-> FALSE] ; 
process Proc1 \in 1..M
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
process Proc2 \in (M+1)..N
variables j2 = 0 ; failed2 = FALSE ; 
begin
2start : while TRUE
         do 2l1 : b[self] := TRUE ;
            2l2 : x := self ;
            2l3 : if y # 0
                   then 2l4 : b[self] := FALSE ;
                        2l5 : when y = 0 ; skip ;
                   else 2l6 : y := self ;
                        2l7 : if x # self 
                               then 2l8 : b[self] := FALSE ;
                                         j2 := 1 ;
                                    2l9 : while (j2 \leq N)
                                           do when ~b[j2] ;
                                              j2 := j2+1 ;
                                         end while ;
                                    2l10 : if y # self
                                            then when y = 0 ;
                                                 failed2 := TRUE ;
                                          end if;
                             end if ;
                        2cs : if ~ failed2
                               then       skip ; \* the critical section
                                    2l11 : y := 0 ;
                                    2l12 : b[self] := FALSE ;
                               else failed2 := FALSE ;
                             end if ;
                  end if ;
        end while ;
end process
end algorithm

**********************
*)
====
