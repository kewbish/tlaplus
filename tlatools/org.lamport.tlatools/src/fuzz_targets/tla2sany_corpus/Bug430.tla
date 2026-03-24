---------------------------- MODULE SubmodParsingError -------------------------
(* It appears that naming a theorem after a submodule raises a parsing error. *)


--------------- MODULE Inner -------------------

================================================


THEOREM T == TRUE
(* SANY raises ***Parse Error***
Encountered "THEOREM Beginning of definition"
*)

THEOREM TRUE  (* no parsing error *)

================================================================================
