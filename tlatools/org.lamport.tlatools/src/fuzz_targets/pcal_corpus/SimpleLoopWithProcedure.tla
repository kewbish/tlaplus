---- MODULE SimpleLoopWithProcedure ----
(*
--algorithm SimpleLoopWithProcedure                                     
     variable x = 0; y \in {1, 2}; n = 0; i = 0;                         
     procedure Incr(incr = 0)                                                
      variable z = 2;                                                    
      begin i1 : x := incr + z + x;                                      
            i2 : return;                                                 
     end procedure                                                       
     begin a : while i < 10                                              
                 do   when Print(x, TRUE);                               
                      i := i + 1 ;                                       
                      call Incr(y) ;                                     
               end while ;                                               
     end algorithm
*)
====
