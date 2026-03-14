---- MODULE NoLoop ----
(*
--algorithm NoLoop
    variable x = 0; y = 0 ;
    begin a : with i = 3 do x := i ; end with;
          b : with j \in { 1 , 2 } do y := j ; x := x + y ; end with ;
          c : if y = 1 then x := x + 1 ; else x := x + y; end if;
              when Print ( x , TRUE );
    end algorithm
*)
====
