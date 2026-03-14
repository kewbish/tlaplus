---- MODULE TreeBarrier ----
(*
--algorithm TreeBarrier
   variables arrived = [i \in 1..2 |-> [j \in 1..N |-> 0]];
             proceed = [i \in 1..2 |-> [j \in 1..N |-> 0]];
   process i \in 1..N
       variables b = 1;
                 p = 0;
       begin
prc:   while (TRUE) do
comp:     skip;
b1:       if 2*self \leq N then
b2:          when arrived[b][2*self] = 1; arrived[b][2*self] := 0;
b3:          when arrived[b][2*self + 1] = 1; arrived[b][2*self + 1] := 0;
             end if;
b4:       arrived[b][self] := 1;
b5:       if self = 1 then
             p := 1;
b6:          while (p \leq N) do
b7:             proceed[b][p] := 1;
                p := p + 1;
                end while;
             end if;
b8:       when proceed[b][self] = 1; proceed[b][self] := 0;
b9:       b := IF b = 1 THEN 2 ELSE 1;
          end while;
       end process;
end algorithm
*)
====
