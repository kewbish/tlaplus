---- MODULE FairSeq ----
(*
--algorithm FairSeq {
    variable x = 0 ;
    fair { while (x < 10) {
            x := x+1;
         }
    }
}
 **************************************************************************
*)
====
