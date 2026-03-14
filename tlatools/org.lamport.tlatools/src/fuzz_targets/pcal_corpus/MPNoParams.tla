---- MODULE MPNoParams ----
(*
--algorithm MPNoParams
    variables sum = 0; 

    procedure Sum ()
      begin s1: sum := sum + 1;
                return;
      end procedure;
    process P1 = 1 
    begin p1 : call Sum();
          p2 : when sum = 4 ;
    end process 
    process P2 \in 2..4 
     begin
          q1 : call Sum();
          q2 : when sum = 4 ;
   end process 
   end algorithm
*)
====
