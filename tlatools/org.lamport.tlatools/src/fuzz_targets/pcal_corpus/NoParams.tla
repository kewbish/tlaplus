---- MODULE NoParams ----
(*
--algorithm NoParams
    variables sum = 0 ;
    procedure Sum() 
      begin s1: sum := sum + 1;
                return;
      end procedure;
    begin m1 : call Sum();
          m2 : call Sum();
          m3 : when Print(sum, TRUE) ;
   end algorithm
*)
====
