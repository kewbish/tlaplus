---- MODULE TestTabs ----
(*
--algorithm TestTabs
  variables x = 0 ;
  begin
l:  x := IF /\ \A i \in {1} : 1 + 1 = 2
	    /\ \A i \in {1} : 2 + 2 = 4
  	    /\	\/ \A i \in {1} : 
		   1 = 0
		\/ \A i \in {1} : 1 = 2
 	        \/ \A i \in {1} : 1 = 1
          THEN 1
          ELSE 0 ;
    assert x = 1 ;
  end algorithm
*)
====
