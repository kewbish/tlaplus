---- MODULE StackTest ----
(*
--algorithm StackAndPCTest
   procedure P(a=42)
      begin P1: stack[self][1].a := stack[self][1].a + 1;
                assert Head(stack[self]).a = 43 ;
                assert pc[self] = "P1" ;
            P2: return
      end procedure
   process Q \in 0..2
     begin Q1: assert \A i \in ProcSet : pc[i] \in {"P1", "P2", "Q1", "Done"};
               call P(22) ;
     end process;
   end algorithm
 **************************************************************************
*)
====
