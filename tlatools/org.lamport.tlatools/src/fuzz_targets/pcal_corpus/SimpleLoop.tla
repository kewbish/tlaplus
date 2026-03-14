---- MODULE SimpleLoop ----
(*
--algorithm SimpleLoop                                                  
     variable x = 0;                                                     
     begin a : while x < 10                                              
                 do x := x+1 ;                                           
                    skip ;                                               
                    assert x \in 1..10;                                             
               end while ;                                               
     end algorithm
*)
====
