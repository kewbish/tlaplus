---- MODULE Peterson ----
(*
--algorithm Peterson {
   variables flag = [i \in {0, 1} |-> FALSE], turn = 0;
   process (proc \in {0,1}) {
     a0: while (TRUE) { 
     a1:   flag[self] := TRUE; 
     a2:   turn := Not(self);       
     a3:   while (flag[Not(self)] /\ turn = Not(self)) {
             skip };
     cs:   skip;  \* critical section   
     a4:   flag[self] := FALSE;            
     } \* end while
    } \* end process
  }
************************************************************************)

(***************************************************************************)
(* Here is the TLA+ translation of the +Cal code, obtained by running pcal *)
(* with the -wf option, which defines Spec to be a specification that      *)
(* assumes weak fairness of the next-state actions of both processes.      *)
(* This fairness assumption is discussed below.                            *)
(**************************************************************************
*)
====
