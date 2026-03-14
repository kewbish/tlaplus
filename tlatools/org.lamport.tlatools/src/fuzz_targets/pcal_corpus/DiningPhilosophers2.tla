---- MODULE DiningPhilosophers2 ----
(*
--algorithm DiningPhilosophers

variable sem = [i \in 0..(N-1) |-> 1] ; 
  procedure foo () 
    begin l2 :+ skip;
          e :+ skip;
          l3 :+ skip;
          p4 : skip ;
          return ;
    end procedure

  procedure foo2 ()
     begin foo2begin : skip;
           return;
     end procedure ;

  fair process DummyProcessSet \in -3..0
   begin dp1: skip ;
   end process

  fair process DummySingleProc = -42
    begin dp1: skip ;
    end process;

  fair process Proc \in 1..(N-1)
begin 
l1 : while TRUE
       do      when sem[self] = 1 ;      \* Get right fork.
               sem[self] := 0 ;
       fox :+ when sem[(self-1) % N] = 1 ; \* Get left fork.
            sem[(self-1) % N] := 0 ;
       e  :+ skip ;                       \* Eat
       l3 :+ sem[self] := 1 ;             \* Release right fork.
       l4 :+ sem[(self-1) % N] := 1 ;     \* Release left fork.
      end while ;
end process

process Leader = 0 \* Proc0 = 0
begin
l01 : while TRUE
         do       when sem[N-1] = 1 ;      \* get left fork
                  sem[N-1] := 0 ;
            l2xx : when sem[0] = 1 ;    \* get right fork
                  sem[0] := 0 ;
            exx  : call foo() ; \* eat
            l03 :+ sem[0] := 1 ;         \* release left fork
                   call foo() ; 
            l04 :+ sem[N-1] := 1 ;        \* release right fork
      end while ;
end process

end algorithm

**********************
*)
====
