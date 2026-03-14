---- MODULE OptionalSemicolonTest_noOptionalSemiColonVariableList4_4 ----
(*
--algorithm algo
variables foo = 0
process bug = 0
fairbegin
L:
    skip
end process

end algorithm
*)
====
