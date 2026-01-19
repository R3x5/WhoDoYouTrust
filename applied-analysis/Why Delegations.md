First, let us define a user, **Alice**, who intends to access a certain service, while explicitly _not_ being permitted to ***directly*** access some sensitive or privileged services.

Alice may initially attempt to log on to **A**, and then access **B** from **A**. However, this approach does not work, because **B has no way of knowing “that you are Alice.”**

### What is Kerberos Double Hop?

Assume that Alice logs on to her own machine. In doing so, she completes the **AS phase** of Kerberos authentication. (see [asktgt](https://github.com/R3x5/WhoDoYouTrust/blob/main/protocol-semantics/asktgt.md))

#### 1. Alice logs on her own machine

```C
Alice@CLIENT → KDC
AS-REQ
  - cname = Alice
```

```C
KDC → Alice@CLIENT
AS-REP
  - Ticket      = TGT(Alice)
  - session_key = Kc,tgs
```

Upon completion of the AS phase, Alice’s client now possesses a **TGT (Alice)**, and this TGT exists only on Alice’s client.

#### 2. Alice accesses A

Subsequently, Alice accesses **A** (for example via WinRM, CIFS, or HTTP), which initiates the TGS phase.

```C
Alice@CLIENT → KDC
TGS-REQ
  - Ticket = TGT(Alice)
  - sname  = A (HOST/A, HTTP/A, CIFS/A)
```

```C
KDC → Alice@CLIENT
TGS-REP
  - Ticket = TGS(Alice → A)
```

```C
Alice@CLIENT → A
AP-REQ
  - Ticket = TGS(Alice → A)
```

Once the TGS phase completes, Alice reaches **A**. Up to this point, everything behaves as expected. From A’s perspective, it observes only a **TGS**, and never the TGT itself.

The critical point is that, at this stage, **A holds a service ticket (TGS: Alice → A) and a local access token representing Alice**. This also precisely explains why, on machine A, the effective identity is Alice, yet B does not recognize her. A does not possess **TGT (Alice)**, and therefore has no ability to initiate a **TGS-REQ** to the KDC on Alice’s behalf (see [asktgs](https://github.com/R3x5/WhoDoYouTrust/blob/main/protocol-semantics/asktgs.md)).

#### 3. A accesses B on behalf of Alice

```C
A → KDC
TGS-REQ
  - Ticket = ???  // Where is the TGT?
  - sname  = B
```

Because A lacks Alice’s TGT, it is unable—at the protocol level—to construct a valid TGS-REQ for Alice, which results in failure. This is the **Kerberos double-hop problem**: ***put simply, the second TGS-REQ cannot be issued.***


### Unconstrained Delegation

One possible way to address this issue is through **unconstrained delegation**, provided that **A is configured for unconstrained delegation**.

```C
Alice@CLIENT → KDC
TGS-REQ
  - Ticket = TGT(Alice)
  - sname  = A
  - forwardable = true
```

```C
KDC → Alice@CLIENT
TGS-REP
  - Ticket = TGS(Alice → A)
  - + TGT(Alice)     // Store it in LSASS
```

***In practice, it is not Alice who hands her ticket to A. Instead, when Alice accesses A, because A is marked as TRUSTED_FOR_DELEGATION, the KDC supplies A with a forwardable ticket on behalf of Alice in TGS-REP phase. A then invokes the appropriate LSASS APIs to store this ticket within its own LSASS process.***

Now **A** can accesses **B** on behalf of **Alice** because it grants her TGT.

```C
A → KDC
TGS-REQ
  - Ticket = TGT(Alice)
  - sname  = B
```

```C
KDC → A
TGS-REP
  - Ticket = TGS(Alice → B)
```

```C
A → B
AP-REQ
  - Ticket = TGS(Alice → B)
```



### Constrained Delegation


> You can see more here
> https://github.com/R3x5/WhoDoYouTrust/blob/main/applied-analysis/Constrained%20Delegation%20With%20Or%20Without%20PT.md

