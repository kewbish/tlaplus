---- MODULE CDiningPhilosophers ----
(*
--algorithm DiningPhilosophers {
  variable sem = [i \in 0..(N-1) |-> 1] ; 

process (Proc \in 1..(N-1)) {
l1 : while (TRUE) {
            { when sem[self] = 1 ;      \* Get right fork.
              sem[self] := 0 } ;
       l2 : { when sem[(self-1) % N] = 1 ; \* Get left fork.
              sem[(self-1) % N] := 0  } ;
       e  : { skip } ;                       \* Eat
       l3 : { sem[self] := 1 } ;             \* Release right fork.
       l4 : { sem[(self-1) % N] := 1 }  ;     \* Release left fork.
      }}

process (Proc0 = 0)
{
l01 : while (TRUE)
          {       when sem[N-1] = 1 ;      \* get left fork
                  sem[N-1] := 0 ;
            l02 : when sem[0] = 1 ;    \* get right fork
                  sem[0] := 0 ;
            e0  : skip ;                 \* eat
            l03 : sem[0] := 1 ;          \* release left fork
            l04 : sem[N-1] := 1 ;        \* release right fork
          }
} }
*******
*)
====
