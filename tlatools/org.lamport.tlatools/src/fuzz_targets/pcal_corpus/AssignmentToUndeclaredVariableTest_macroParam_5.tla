---- MODULE AssignmentToUndeclaredVariableTest_macroParam_5 ----
(*
--algorithm algo {
  variables v;
  macro Mac2(p) { p := "pmac"}
 {
  lbl1: Mac2(v);
  lbl2: Mac2(c);
 }
}
*)
====
