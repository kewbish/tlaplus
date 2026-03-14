---- MODULE NoLoop2 ----
(*
--algorithm NoLoop2
    variable x = 0; y = 0 ;
    begin a : with i = 3 do x := i ; end with;
          b : with j \in { 1 , 2 } do y := j ; x := x + y ; end with;
          c : if y = 1 then x := x + 1 ; d : x := 2 * x ;
                       else x := x + y ; end if;
          e : when Print ( x , TRUE );
    end algorithm
   \* should print out 10 or 7
*)
====
