---- MODULE bug_05_12_31 ----
(*
--algorithm Test
   procedure P(a = 7) 
      variable x = a ; y = x+1 ;
      begin P1: assert a = 1;
                assert x = a;
                assert y = a+1;
                return;
      end procedure 
     begin A: call P(1)
  end algorithm
*)
====
