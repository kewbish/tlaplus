---- MODULE SBB ----
(*
--algorithm sbb

    variables
        sb = [ owner |-> NoPid, buf |-> CHOOSE b \in Buf : TRUE ];
        availablebuffers = Buf \ {sb.buf};
        publishedbuffers = {};


    process work \in Pid
        variable
            buf = NoBuf;
        op = {};
    begin
      Loop:
        while TRUE do
            with lop \in { "Publish", "Modify" } do
                op := lop;
            end with;

        if (op = "Publish") then
                buf := sb.buf;          
              Publish1:
                if sb.owner # self /\ sb.owner # NoPid then
                    buf := CHOOSE b \in availablebuffers : TRUE;
                    availablebuffers := availablebuffers \ {buf};
                else
                  Publish2:
                    sb.owner := NoPid;
                end if;
              Publish3:
                publishedbuffers := publishedbuffers \cup {buf};


            else
                buf := sb.buf;
              Modify1:
                if sb.owner # self then
                    buf := CHOOSE b \in availablebuffers : TRUE;
                    availablebuffers := availablebuffers \ {buf};
                end if;
              Modify2:
              \* assert buf \notin publishedbuffers;
                sb.owner := self;
              Modify3:
                sb.buf := buf;
            end if
        end while;
    end process;
end algorithm
*)
====
