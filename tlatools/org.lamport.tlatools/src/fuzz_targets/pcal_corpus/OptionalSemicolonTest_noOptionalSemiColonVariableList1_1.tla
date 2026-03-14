---- MODULE OptionalSemicolonTest_noOptionalSemiColonVariableList1_1 ----
(*
--algorithm algo
variables foo = 0
fair process bug = 0
fairbegin
L:
    skip
end process

end algorithm
*)
====
