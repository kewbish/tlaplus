---- MODULE Fischer ----
(*
--algorithm Fischer
  variables x = 0 ; timer = [i \in 1..N |-> Infinity] ;
  process Proc \in 1..N
   variable firstTime = TRUE ;
   begin a : while TRUE             
     (**********************************************************************)
     (* Note that the +cal syntax requires that both while statements be   *)
     (* labeled, adding a useless atomic action.  The only ways I see to   *)
     (* eliminate that would be by adding a "goto" statement that could be *)
     (* used to encode the inner "while" loop.                             *)
     (**********************************************************************)
              do b : while x # self  
                        (***************************************************)
                        (* x can't equal i the first time through the loop *)
                        (***************************************************)
                       do c : when x = 0 ;
                              timer[self] := Delta ;
                          d : x := self ; 
                              timer[self] := Epsilon ;
                          e : when timer[self] = 0 ;
                              timer[self] := Infinity ;
                     end while ; 
                cs : skip ;  \* critical section
                 f : x := 0 ;
             end while ;
   end process  
  process Tick = 0
    begin t1 : while TRUE
                 do when \A i \in 1..N : timer[i] > 0 ;
                    timer := [i \in 1..N |-> IF timer[i] < Infinity
                                           THEN timer[i] - 1 
                                           ELSE timer[i] ] ;
               end while ;
   end process
end algorithm

**********************
*)
====
