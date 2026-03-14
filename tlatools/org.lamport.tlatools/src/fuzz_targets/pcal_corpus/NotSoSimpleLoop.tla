---- MODULE NotSoSimpleLoop ----
(*
--algorithm NotSoSimpleLoop                                             
     variable x = 0;                                                     
     begin a : while x < 10                                              
                 do x := x+1 ;                                           
                    skip ;                                               
                    assert x \in 1..10
               end while ;                                               
               x := 4*x ;                                                
               assert x = 40 ;                                                 
           b : assert 2 * x = 80;                                             
     end algorithm
*)
====
