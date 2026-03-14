---- MODULE ReallySimpleMultiProc ----
(*
--algorithm SimpleMultiProc                                             
     variables                                                           
       x = [i \in ProcSet |-> CASE i = 41 -> 1 []                         
                                  i = 42 -> 2 []                         
                                  i = 43 -> 3];                          
       sum = 0 ;                                                         
       done = {};                                                        
     process ProcA = 41                                                  
       variable y = 0;                                                   
       begin a1 : sum := sum + y + x [ 41 ] ||                           
                  done := done \cup { 41 } ;                             
             a2 : when done = { 41, 42, 43 } ;                           
                  when Print ( sum , TRUE ) ;                            
       end process                                                       
     process ProcB \in {42, 43}                                          
       variable z \in {2, 3} ;                                           
       begin b1 : sum := sum + z + x [ self ] ;                          
             b2 : done := done \cup { self } ;                           
       end process                                                       
     end algorithm
*)
====
