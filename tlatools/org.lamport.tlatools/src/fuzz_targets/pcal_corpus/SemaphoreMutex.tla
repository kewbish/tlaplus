---- MODULE SemaphoreMutex ----
(*
--algorithm SemaphoreMutex
variables sem = 1 ; 
macro P(s) begin when s > 0 ;
                 s := s - 1 ;
end macro

macro V(s) begin s := s + 1 ;
end macro

process Proc \in 1..N
begin
start : while TRUE
         do enter : P(sem) ;
            cs    : skip ;
            exit  : V(sem) ;
        end while ;
end process
end algorithm


**********************
*)
====
