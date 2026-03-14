---- MODULE AssignmentToUndeclaredVariableTest_process_2 ----
(*
--algorithm algo {
  variables v, w;
  process (proc \in {1,2})
    variable loc
 {
   lbl1: loc := 42;
   lbl2: v := 23;
   lbl3: w := 174;
   lbl4: c := "fail";
 }
}
*)
====
