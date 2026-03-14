---- MODULE PcalPaxos ----
(*
--algorithm Paxos
  variables msgs = {}; 
  macro Send(m) 
   begin msgs := msgs \cup {m}
   end macro

  process Ldr \in Leader
    variables ldrBal = -1 ;
              ldrPhs = 2 
    begin L: 
      while TRUE do
        with b \in {bb \in Ballot : LeaderOf[bb] = self}
          do either when ldrBal < b;
                    ldrBal := b ;
                    ldrPhs := 1 ;
                    Send([type |-> "1a", bal |-> b])

             or     when (ldrBal = b) /\ (ldrPhs = 1) ;
                    with M = {m \in msgs : (m.type = "1b") /\ (m.bal = b)};
                         A = {m.acc : m \in M} ;
                         mmsg \in {m \in M : 
                                    \A m2 \in M : m.mbal \geq m2.mbal}
                       do when A \in Majority ;
                          if mmsg.mbal > -1
                            then Send([type |-> "2a", bal |-> b, 
                                       cmd |-> mmsg.mcmd])
                            else with c \in Command
                                   do Send([type |-> "2a", bal |-> b, 
                                            cmd |-> c])
                                 end with
                          end if ;
                     end with ;
                     ldrPhs := 2
                end either
             end with
      end while
    end process

  process Acc \in Acceptor
    variables bal = -1 ; mbal = -1 ; mcmd = NotACmd
    begin A: 
      while TRUE do 
        with m \in msgs
          do either when (m.type = "1a") /\ (m.bal > bal) ;
                    bal := m.bal ;
                    Send([type |-> "1b", bal |-> m.bal, acc |-> self,
                          mbal |-> mbal, mcmd |-> mcmd])
             or     when    (m.type = "2a")
                         /\ (m.bal \geq bal) 
                         /\ (m.bal > mbal);
                    bal  := m.bal ;
                    mbal := m.bal ;
                    mcmd := m.cmd ;
                    Send([type |-> "2b", bal |-> m.bal, acc |-> self,
                           cmd |-> m.cmd])
             end either
        end with
      end while
    end process


  process Lrn \in Learner
    variable learned = NotACmd
    begin N: with b \in Ballot ;
                  2bMsgs = {m \in msgs : (m.type = "2b") /\ (m.bal = b)}
               do when {m.acc : m \in 2bMsgs} \in Majority ;
                  with m \in 2bMsgs
                    do learned := m.cmd
                  end with
             end with ;
    end process
end algorithm
*)
====
