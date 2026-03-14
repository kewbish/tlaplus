---- MODULE bug_06_01_25 ----
(*
--algorithm TestAlignment
   variable x ; y ; z = /\ \A i \in {1} : i > 0 
                        /\ \A i \in {1} : i > 0 
                        /\ \A i \in {1} : i > 0 
   define  foo == /\ \A i \in {1} : i > 0 
                  /\ \A i \in {1} : i > 0 
                  /\ \A i \in {1} : i > 0 
   end define;
   macro Mac(a) begin x := \A i \in {1} : i > 0 ;
                      y := \A i \in {1} : i > 0 ;
                      z := \A i \in {1} : i > 0 ;
                      assert /\ \A i \in {1} : i > 0 
                             /\ \A i \in {1} : i > 0 
                             /\ \A i \in {1} : i > 0  ;
                      assert a 
   end macro;
     
   procedure P(a = /\ \A i \in {1} : i > 0 
                   /\ \A i \in {1} : i > 0 
                   /\ \A i \in {1} : i > 0)
      begin P1: x := \A i \in {1} : i > 0 ;
                y := \A i \in {1} : i > 0 ;
                z := \A i \in {1} : i > 0 ;
                return
      end procedure
   process Q \in {qq \in {1,2} : /\ \A i \in {1} : i > 0 
                                 /\ \A j \in {1} : j > 0 
                                 /\ \A k \in {1} : k > 0 }
     variable w = /\ \A i \in {1} : i > 0 
                  /\ \A i \in {1} : i > 0 
                  /\ \A i \in {1} : i > 0 
      begin P1: if /\ \A i \in {1} : i > 0 
                   /\ \A i \in {1} : i > 0 
                   /\ \A i \in {1} : i > 0  then x := \A i \in {1} : i > 0 ;
                                                 y := \A i \in {1} : i > 0 ;
                                                 z := \A i \in {1} : i > 0 
                  else x := \A i \in {1} : i > 0 ;
                       y := \A i \in {1} : i > 0 ;
                       z := \A i \in {1} : i > 0                       
                 end if ;
           P15:  with k  \in {kk \in {2,3} : /\ \A i \in {1} : i > 0 
                                             /\ \A i \in {1} : i > 0 
                                             /\ \A i \in {1} : i > 0 } do
                   with m = /\ \A i \in {1} : i > 0 
                            /\ \A i \in {1} : i > 0 
                            /\ \A i \in {1} : i > 0  do
                    x := \A i \in {1} : i > 0 ;
                    y := \A i \in {1} : i > 0 ;
                    z := \A i \in {1} : i > 0  
                 end with end with ;
            P2: while /\ \A i \in {1} : i > 0 
                      /\ \A i \in {1} : i > 0 
                      /\ \A i \in {1} : i > 0 
                      /\ FALSE do
                   x := \A i \in {1} : i > 0 ;
                   y := \A i \in {1} : i > 0 ;
                   z := \A i \in {1} : i > 0 ;
                   w := /\ \A i \in {1} : i > 0 
                        /\ \A i \in {1} : i > 0 
                        /\ \A i \in {1} : i > 0 
                end while ;
            P3: call P(/\ \A i \in {1} : i > 0 
                       /\ \A i \in {1} : i > 0 
                       /\ \A i \in {1} : i > 0) ;
            P4: assert /\ \A i \in {1} : i > 0 
                       /\ \A i \in {1} : i > 0 
                       /\ \A i \in {1} : i > 0 ;
                print  /\ \A i \in {1} : i > 0 
                       /\ \A i \in {1} : i > 0 
                       /\ \A i \in {1} : i > 0 ;
            P5: Mac(/\ \A i \in {1} : i > 0 
                    /\ \A i \in {1} : i > 0 
                    /\ \A i \in {1} : i > 0 )
     end process
   end algorithm
*)
====
