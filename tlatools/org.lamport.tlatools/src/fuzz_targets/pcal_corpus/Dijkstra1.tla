---- MODULE Dijkstra1 ----
(*
--algorithm Dijkstra1
variable M \in [ProcSet -> 0..(K-1)];

  process P0 = 0
    begin
p0: while TRUE do
      when M[0] = M[N-1];
p1:   M[0] := (M[0] + 1) % K;
      end while
    end process;

  process Pi \in 1..(N-1)
    begin
pi: while (TRUE) do
      when M[self] # M[self - 1];
pj:   M[self] := M[self - 1];
      end while
    end process;

  end algorithm
*)
====
