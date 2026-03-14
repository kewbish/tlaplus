---- MODULE OptionalSemicolonTest_noOptionalSemiColonVariableList3_3 ----
(*
--algorithm algo
variables foo = 0 ;
process bug = 0
fairbegin
L:
    skip
end process

end algorithm
*)
====
