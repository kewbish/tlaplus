---- MODULE bug_05_12_16b ----
(*
--algorithm Dijkstra1
  procedure Foo(a = 1) 
   variable x = 42 ; y = x 
   begin Foo1: return ;
   end procedure
  process P \in 1..3
    begin 
    P1: assert x = y ;
        skip ; 
    P2: call Foo(17) ;
    end process;

  end algorithm
*)
====
