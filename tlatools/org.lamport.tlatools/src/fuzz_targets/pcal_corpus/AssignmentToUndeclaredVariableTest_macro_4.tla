---- MODULE AssignmentToUndeclaredVariableTest_macro_4 ----
(*
--algorithm algo {
  variables v;
  macro Mac() { v := "pmac";
 c := 42; }
 {
  Mac();
 }
}
*)
====
