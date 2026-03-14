---- MODULE AssignmentToUndeclaredVariableTest_multiAssignment_3 ----
(*
--algorithm algo {
  variables v, w;
 {
  v := 42 || w := 23;
  v := 42 || c := 23;
 }
}
*)
====
