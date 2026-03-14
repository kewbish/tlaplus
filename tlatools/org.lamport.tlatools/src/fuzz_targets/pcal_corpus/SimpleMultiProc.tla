---- MODULE SimpleMultiProc ----
(*
--algorithm SimpleMultiProc                                             
     variables                                                           
       x = [i \in ProcSet |-> CASE i = 41 -> 1 []                         
                                   i = 42 -> 2 []                         
                                   i = 43 -> 3 []                         
                                   i = 44 -> 4 []                         
                                   i = 45 -> 5];                          
       sum = 0 ;                                                         
       done = {};
     procedure AddMe(me = 0)
       variable y = 0;
       begin am: done := done \cup { me } ;
                 return ;
       end procedure                                                         
     process ProcA = 41                                                  
       variable y = 0;                                                   
       begin a1 : sum := sum + y + x [ 41 ] ||
                  y := sum ;                           
             a2 : call AddMe(41) ;                             
             a3 : when done = { 41, 42, 43, 44, 45 } ; 
       end process                                                       
     process ProcB \in 42 .. 43                                          
       variable z \in {2, 3} ;                                           
       begin b1 : sum := sum + z + x [ self ] ;                          
             b2 : call AddMe(self);                           
       end process                                                       
     process ProcC \in { 44,
                         45 }                                          
       variable z \in {4, 5} ;                                           
       begin c1 : sum := sum + z + x [ self ] ;                          
             c2 : call AddMe(self) ;                           
       end process                                                       
     end algorithm
*)
====
