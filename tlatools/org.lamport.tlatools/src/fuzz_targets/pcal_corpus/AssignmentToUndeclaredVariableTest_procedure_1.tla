---- MODULE AssignmentToUndeclaredVariableTest_procedure_1 ----
(*
--algorithm algo {
  variables v, w;
    procedure Proc1() 
      {p1 : v := 23;
            c := 42 }
 {
  i: call Proc1();
 }
}
*)
====
