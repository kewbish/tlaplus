---- MODULE bug_05_12_10a ----
(*
--algorithm Pcal
  procedure IsAlgorithm(A)
    variable res = FALSE ; i = 0 ;
    begin IA1: assert \/ /\ A.type = "uniprocess"
                         /\ DOMAIN A = {"type", "name", "defs", 
                                           "decls", "prcds", "body"}
                      \/ /\ A.type = "multiiprocess"
                         /\ DOMAIN A = {"type", "name", "defs", 
                                            "decls", "prcds", "procs"};
               assert A.name \in STRING ;
               call IsExpr(A.defs) ;
          IA2: assert IsSeq(A.decls) ;
               i := Len(A.decls) ;
          IA3: while i > 0 do call IsVarDecl(A.decls[i]) ;
                        IA3a: i := i-1 
               end while ;
               i := Len(A.prcds) ;
          IA4: while i > 0 do call IsProcedure(A.prcds[i]) ;
                        IA4a: i := i-1 
               end while ;
               if A.type = "uniprocess"
                 then assert IsNonemptySeq(A.body) ;
                             i := Len(A.body) ;
                 IA5: while i > 0 do call IsLabeledStmt(A.body[i])  ;
                               IA5a: i := i-1 
                      end while ;
                 else assert IsNonemptySeq(A.procs) ;
                             i := Len(A.procs) ;
                 IA6: while i > 0 do call IsProcess(A.procs[i])  ;
                               IA6a: i := i-1 
                      end while ;
               end if ;
          IA7: return ;
    end procedure
  procedure IsExpr(exp)
    variable i ;
    begin IE1 : assert IsSeq(exp) ;
               i := Len(exp) ;
          IE2: while i > 0 do assert exp[i] \in STRING  ;
                        IA5a: i := i-1 
               end while ;
               return               
    end procedure
  procedure IsVarDecl(vdcl)
    begin IV1 : return 
    end procedure
  procedure IsProcedure(prcdr)
    begin IP1 : return 
    end procedure
  procedure IsLabeledStmt(lstmt)
    begin IL1 : return 
    end procedure
  procedure IsProcess(proc)
    begin IPr1 : return 
    end procedure
  begin PC1: call IsAlgorithm(alg) ;
        Pc2: print "IsAlgorithm(alg) = TRUE"
  end algorithm
*)
====
