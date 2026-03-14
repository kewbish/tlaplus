---- MODULE StarkMutex ----
(*
--algorithm StarkMutex
  variables flag = [i \in 1..N |-> FALSE]; 
            next = 1;
            empty = TRUE;
            mutex = 1;
            weakSem = [i \in 1..N |-> 0];
  process i \in 1..N
    variables first = FALSE;
              j = 1;
    begin
    in1: while (TRUE) do
         flag[self] := TRUE;
         first := FALSE;
    in2: when mutex = 1; mutex := 0;
    in3: if empty then
    in4:    empty := FALSE;
            first := TRUE;
            end if;
    in5:    mutex := 1;
    in6:    if ~ first then
               when weakSem[self] = 1; weakSem[self] := 0;
             end if;
    cs:     skip;
    ex1:    flag[self] := FALSE;
    ex2:    when mutex = 1; mutex := 0;
    ex3:    j := 1;
            empty := TRUE;
    ex4:    while j \leq N do
               if flag[IF next + j > N THEN next + j - N ELSE next + j] then
    ex5:          with n = IF next + j > N THEN next + j - N ELSE next + j do
                     next := n;
                     weakSem[n] := 1;
                     j := N + 1;
                     end with;
    ex6:          empty := FALSE;
               else
    ex7:          j := j + 1;
               end if;
            end while;
    ex8:    mutex := 1;
    nc:     skip;
            end while;
    end process
  end algorithm
*)
====
