---- MODULE bug_05_10_03 ----
(*
--algorithm showBug

process Proc \in 1..2 
variables x=[f1 |-> 1 , f2|->self ];

begin 
start: x.f1:=self;
       assert x.f1 = self;
end process;
    
end algorithm
*)
====
