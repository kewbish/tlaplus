---- MODULE SyncCons ----
(*
--algorithm SyncCons
        variables clock = 0;
                  input \in Data;
          round = [i \in 1..N |-> 0];
          buffer= { };
          crashed = { };

\***** Macros for sending and receiving messages
       macro Send(i, j, msg)
       begin 
       buffer := buffer \cup
         {[from |->  i,
           to   |->  j,
           msg  |-> IF i \in crashed
                     THEN bot
                      ELSE msg]};
       end macro

       macro Receive(i, j, msg)
       begin 
       when [from |->  i,
             to   |->  j,
             msg  |-> msg] \in buffer;
       buffer := buffer 
                   \ {[from |->  i,
                       to   |->  j,
                       msg  |-> msg]};
       end macro

\***** Synchronous consensus protocol for crash failures
\***** A crashed process sends "bot" messages, which model timeouts
       process Participant \in 1..N
        variables output = bot;
                  procs = { };
                  value = IF self = 1
                            THEN input
                            ELSE bot;
          recd = { };
          begin
s1:         while round[self] < t + 1 do
              when round[self] = clock;
              procs := 1..N;
s2:           while procs # { } do
                with dest \in procs do
                  Send(self, dest, value);
                  procs := procs \ {dest};
                  end with
                end while;
s3:           if self \notin crashed then
                procs := 1..N;
                recd := { };
s4:             while procs # { } do
                  with source \in Proc do
                    with data \in Data \cup {bot} do
                      Receive(source, self, data);
                      recd := recd \cup {data};
                      procs := procs \ {source};
                      end with
                    end with
                  end while;
s5:             if recd \cap Data = { }
                   then value := bot;
                   else value := CHOOSE i \in Data:
                                   i \in recd \cap Data;
                   end if;
                end if;
s6:           round[self] := round[self] + 1;
              end while;
            output := IF value = bot
                         THEN 0
                         ELSE value;  
            end process;
              
\***** Model of clock: ticks when all processes finish the current round
       process Clock = N + 1
         begin
clock:     while clock < t + 1 do
             when \A i \in 1..N: round[i] = clock + 1;
             clock := clock + 1;
             end while;
           end process;

\***** Crashing processes
       process Crash = N + 2
         begin
crash:     while Cardinality(crashed) < t do
             with x  \in (1..N) \ crashed do
               crashed  := crashed \cup {x}
               end with
             end while
           end process;

end algorithm
*)
====
