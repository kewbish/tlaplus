-------------------------------- MODULE test65 --------------------------------
EXTENDS test65a
 
I == INSTANCE test65a WITH c <- 42
J == INSTANCE test65a WITH c <- 44
ASSUME /\ <<I!foo, J!foo>>  = <<42, 44>>
       /\ foo = c
=======================================================================

----- CONFIG test65 -----
CONSTANT c = "a"
====
