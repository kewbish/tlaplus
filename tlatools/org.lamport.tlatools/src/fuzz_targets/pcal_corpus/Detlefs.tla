---- MODULE Detlefs ----
(*
--algorithm Snark {
variables Mem = [i \in Address |-> IF i = Dummy THEN DummyNode ELSE InitNode],
          freeList = Address \ {Dummy},
          LeftHat  = Dummy,
          RightHat = Dummy,
          rVal = [i \in Procs |-> "okay"] ,   \* Used for returning values
          valBag = [i \in Val |-> 0] ;
            \* For testing: valBag[i] is the number of copies of i 
            \* that can be in the queue.

macro New(result) {
  if (freeList # {}) {
    result := CHOOSE a \in freeList : TRUE ;
    freeList := freeList \ {result} ;
  } else result := null
}

macro DCAS(result, addr1, addr2, old1, old2, new1, new2) {
  if ( /\ addr1 = old1
       /\ addr2 = old2) { 
    addr1 := new1 ||
    addr2 := new2 ;
    result := TRUE; 
  } else result := FALSE; } 


\* val pushRight(val v) { 
\*   nd = new Node(); /* Allocate new Node structure */ 
\*   if (nd == null) return "full"; 
\*   nd�>R = Dummy; 
\*   nd�>V = v; 
\*   while (true) { 
\*     rh = RightHat;                           /* Labels A, B,   */ 
\*     rhR = rh�>R;                             /* etc., are used */ 
\*     if (rhR == rh) {                         /* in the proof   */ 
\*       nd�>L = Dummy;                         /* of correctness */ 
\*       lh = LeftHat; 
\*       if (DCAS(&RightHat, &LeftHat, rh, lh, nd, nd))      /* A */ 
\*         return "okay"; 
\*     } else { 
\*       nd�>L = rh; 
\*       if (DCAS(&RightHat, &rh�>R, rh, rhR, nd, nd))      /* B */ 
\*         return "okay"; 
\* } } } // Please forgive this brace style 

procedure pushRight(v) 
 variables nd = null , rh = Dummy, rhR = Dummy, lh = Dummy, 
           temp = Dummy ; { 
L1: New(nd) ; 
    if (nd = null) { rVal[self] := "full"; L1a: return } ;
L1b: Mem[nd].R := Dummy ||   \* Since no other thread can access nd here,
     Mem[nd].V := v ; 
L4: while (TRUE) { 
      rh  := RightHat;                           
L5:   rhR := Mem[rh].R;                          
L6:   if (rhR = rh) {                         
        Mem[nd].L := Dummy;                   
        lh := LeftHat; 
L7:     DCAS(temp, RightHat, LeftHat, rh, lh, nd, nd) ;
        if (temp) { 
          rVal[self] := "okay"; L7a: return}
      } else { 
L8:       Mem[nd].L := rh; 
L9:       DCAS(temp, RightHat, Mem[rh].R, rh, rhR, nd, nd) ;
          if (temp) {
            rVal[self] := "okay";  L8a: return }
} } } 


\* val popRight() { 
\*    while (true) { 
\*      rh = RightHat;                     // Delicate order of operations 
\*      lh = LeftHat;                      // here (see proof of Theorem 4 
\*      if (rh�>R == rh) return "empty";   // and the Conclusions section) 
\*      if (rh == lh) { 
\*        if (DCAS(&RightHat, &LeftHat, rh, lh, Dummy, Dummy))     /* C */ 
\*          return rh�>V; 
\*      } else { 
\*        rhL = rh�>L; 
\*        if (DCAS(&RightHat, &rh�>L, rh, rhL, rhL, rh)) {         /* D */ 
\*          result = rh�>V; 
\*          rh�>R = Dummy; /* E */ 
\*          rh�>V = null;                        /* optional (see text) */ 
\*          return result; 
\* } } } }                         // Stacking braces this way saves space 
\* 

procedure popRight()
 variables rh = Dummy, lh = Dummy, rhL = Dummy, 
           temp = Dummy , result = null ; { 
M1: while (TRUE) { 
      rh := RightHat;    
M2:   lh := LeftHat;     
      if (Mem[rh].R = rh) {rVal[self] := "empty"; M2a: return ;} ;
M3:   if (rh = lh) { 
        DCAS(temp, RightHat, LeftHat, rh, lh, Dummy, Dummy) ;
        if (temp) { 
M4:       rVal[self] := Mem[rh].V ; M4a:  return;} 
      } else { 
M5:     rhL := Mem[rh].L ; 
M6:     DCAS(temp, RightHat, Mem[rh].L, rh, rhL, rhL, rh) ;
        if (temp) {         
M7:       result := Mem[rh].V; 
M8:       Mem[rh].R := Dummy ||
          Mem[rh].V := null;  
          rVal[self] := result ; M9a: return ;
} } } }

\* val pushLeft(val v) { 
\*   nd = new Node();      /* Allocate new Node structure */ 
\*   if (nd == null) return "full"; 
\*   nd�>L = Dummy; 
\*   nd�>V = v; 
\*   while (true) { 
\*     lh = LeftHat; 
\*     lhL = lh�>L; 
\*     if (lhL == lh) { 
\*       nd�>R = Dummy; 
\*       rh = RightHat; 
\*       if (DCAS(&LeftHat, &RightHat, lh, rh, nd, nd))          /* A' */ 
\*         return "okay"; 
\*     } else { 
\*       nd�>R = lh; 
\*       if (DCAS(&LeftHat, &lh�>L, lh, lhL, nd, nd))            /* B' */ 
\*         return "okay"; 
\* } } }                        // We were given a firm limit of 15 pages 

procedure pushLeft(v) 
 variables nd = null , rh = Dummy, lhL = Dummy, lh = Dummy, 
           temp = Dummy ; { 
N1: New(nd) ;                          
    if (nd = null) {rVal[self] := "full"; N1a: return ;} ;
N1b: Mem[nd].L := Dummy ||   \* Since no other thread can access nd here,
    Mem[nd].V := v;          \* we can represent this as a single action. 
N2: while (TRUE) { 
    lh := LeftHat;          
N3: lhL := Mem[lh].L; 
    if (lhL = lh) { 
N4:   Mem[nd].R := Dummy; 
N5:   rh := RightHat; 
N6:   DCAS(temp, LeftHat, RightHat, lh, rh, nd, nd) ;
      if (temp) {          
        rVal[self] := "okay";  nd := null ; N6a: return;}
    } else { 
N7:   Mem[nd].R := lh; 
N8:   DCAS(temp, LeftHat, Mem[lh].L, lh, lhL, nd, nd) ;
      if (temp) {          
        rVal[self] := "okay"; nd := null ; N8a: return }
} } }                    
  
\* val popLeft() { 
\*   while (true) { 
\*     lh = LeftHat;                          // Delicate order of operations 
\*     rh = RightHat;                         // here (see proof of Theorem 4 
\*     if (lh�>L == lh) return "empty";       // and the Conclusions section) 
\*     if (lh == rh) { 
\*       if (DCAS(&LeftHat, &RightHat, lh, rh, Dummy, Dummy))        /* C' */ 
\*         return lh�>V; 
\*     } else { 
\*       lhR = lh�>R; 
\*       if (DCAS(&LeftHat, &lh�>R, lh, lhR, lhR, lh)) {             /* D' */ 
\*         result = lh�>V; 
\*         lh�>L = Dummy;                                            /* E' */ 
\*         lh�>V = null;                            /* optional (see text) */ 
\*         return result; 
\* } } } }                     // Better to stack braces than to omit a lemma 

procedure popLeft() 
 variables rh = Dummy, lh = Dummy, lhR = Dummy, 
           temp = Dummy , result = null ; { 
O1: while (TRUE) { 
      lh := LeftHat;                           
O2:   rh := RightHat;                    
O3:   if (Mem[lh].L = lh) {rVal[self] := "empty";  O3a: return ;} ;
O4:   if (lh = rh) { 
      DCAS(temp, LeftHat, RightHat, lh, rh, Dummy, Dummy) ;
      if (temp) {          
O5:     rVal[self] := Mem[lh].V; O5a: return; }
      } else { 
O6:     lhR := Mem[lh].R; 
O7:     DCAS(temp, LeftHat, Mem[lh].R, lh, lhR, lhR, lh) ;
      if (temp) {               
O8:     result := Mem[lh].V; 
O9:     Mem[lh].L := Dummy ||
        Mem[lh].V := null;                              
        rVal[self] := result;  O10a: return ;
} } } }                       


\* process (GarbageCollet = GC) {
\* GC1: while (TRUE) {
\*      with (adr \in Address \ (freeList \cup {Dummy})) {
\*        when Mem[adr].canGC ;
\*        when \A b \in Address \ (freeList \cup {Dummy, adr}) :
\*               /\ adr # Mem[b].L
\*               /\ adr # Mem[b].R ;
\*        freeList := freeList \cup {adr} ;
\*        Mem[adr] := InitNode;
\*      } } }

process (test \in Procs)
variables pushedVal = null ; {
T1: while(TRUE) {
      either { \* push
        with (x \in Val) {pushedVal := x} ;
        valBag[pushedVal] := valBag[pushedVal] + 1 ;
        either  call pushLeft(pushedVal) or call pushRight(pushedVal)  ;
T2:     if (rVal[self] = "full") valBag[pushedVal] := valBag[pushedVal] - 1 
        }
      or { \* pop
        either call popLeft() or call popRight()  ;
T3:     if (rVal[self] # "empty") {
          assert valBag[rVal[self]] > 0 ;
          valBag[rVal[self]] := valBag[rVal[self]] - 1;
        } 
} } }}
*)
====
