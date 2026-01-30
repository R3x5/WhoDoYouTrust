
# Syllabus is like this
```C
Syllabus
└── 🎫 Tickets
		├── 🥇 Golden Ticket
		├── 🥈 Silver Ticket
		└── 📜 PAC
└── 🔗 Delegation
		├── 🪤 Unconstrained Delegation
		├── 🔒 Kerberos Constrained Delegation (KCD)
		└── 🧩 Resource-Based Constrained Delegation (RBCD)
```



# 🎫 Tickets


## 🥇 Golden Ticket

Once an attacker obtains the **`krbtgt` key** of a domain, they are able to forge **Golden Tickets** for that domain. The underlying principle is that the attacker forges the _result_ of the AS phase—namely, the **AS-REP**—directly, without ever issuing an AS-REQ or interacting with the KDC. (see [AS phase](https://github.com/R3x5/WhoDoYouTrust/blob/main/protocol-semantics/asktgt.md))

```C
// attacker controls krbtgt_A

tgt_session_key = random_key();

fake_TGT_A = Encrypt(
    key = krbtgt_A,
    data = {
        sname = "krbtgt/A",
        client = "Administrator@A",
        session_key = tgt_session_key,
        PAC = {
            UserSID = A\DomainSID + RID(500)
        },
        times,
        flags
    }
);
```

In cross-realm scenarios, both Golden Tickets and Silver Tickets undergo important semantic changes, most notably the transition from the **`krbtgt` key** to the **inter-realm trust key**.

When the KDC of the _trusting realm_ receives a cross-realm TGT issued by the _trusted realm_, it attempts to decrypt the ticket using the **trust key**. If decryption succeeds, the ticket—and the **PAC embedded within it**—is accepted as a whole. Consequently, the PAC is created during the **AS or TGS phase of the originating realm**, rather than being generated within the trusting realm.

Once the cross-realm TGT is accepted, the **TGS phase is triggered**. A critical detail here is that, during the **cross-realm TGS-REP phase**, the entire process is handled exclusively by the KDC of the trusting realm. It encrypts the service ticket (ST) using the **service account key** and generates the **service session key**, which is subsequently used in the **AP-REQ** exchange.

```C
// attacker controls trust_key_AB

k_ab = attacker_chosen_key();

fake_interrealm_TGT = Encrypt(
    key = trust_key_AB,
    data = {
        sname = "krbtgt/B",
        client = "Administrator@A",
        session_key = k_ab,

        PAC = {
            UserSID = A\DomainSID + RID(500),
            ExtraSIDs = [
                B\DomainSID + RID(512)   // Domain Admin in B
            ]
        },
        times,
        flags
    }
);
```

```C
service_session_key = random_key();

ST_B = Encrypt(
    key = service_key_B,
    data = {
        client = tgt_plain.client,
        session_key = service_session_key,
        PAC = tgt_plain.PAC,
        times,
        flags
    }
);
```


## 🥈 Silver Ticket

**Silver Tickets** follow the same logic as Golden Tickets. The difference is that Silver Tickets require possession of a **service account key** and involve forging the _result_ of the TGS phase—specifically, the **TGS-REP**—again without any interaction with the KDC. (see [TGS phase](https://github.com/R3x5/WhoDoYouTrust/blob/main/protocol-semantics/asktgs.md))


## 📜 PAC

During the **AS phase**, the **PAC** serves as the _source of authorization_. It is not consumed by any service at that stage; instead, it functions as the **authorization template** for all subsequent service tickets.

During the **TGS phase**, the KDC decrypts the TGT and **inherits, filters, or extends the PAC** (depending on the specific context), after which the PAC is embedded into the resulting service ticket (ST). Accordingly, the PAC is **copied and modified**, rather than being recomputed from scratch.

As a result, no matter how “well-formed” or “privileged” the PAC contained within a TGT may be, it has **zero authorization value** unless it is propagated into the ST. Authorization decisions are made exclusively based on the PAC present in the service ticket.

> The details surrounding `PAC_*_CHECKSUM` structures and their associated validation mechanisms are substantially more complex and are therefore omitted here.

```C
// ticket approximate internal structure

TGT / ST
└── EncTicketPart   (krbtgt / trust key / service key / user key)
    ├── session_key
    ├── times
    ├── flags
    ├── ...
    └── authorization-data
        └── AD-WIN2K-PAC
            ├── PAC_LOGON_INFO   (SID / Groups / ExtraSIDs)
            ├── PAC_SERVER_CHECKSUM
            └── PAC_KDC_CHECKSUM
```


# 🔗 Delegation


## 🪤 Unconstrained Delegation

As **unconstrained delegation** has already been discussed earlier, it will not be repeated here; readers may refer to my previous document for details. (see [unconstrained delegation](https://github.com/R3x5/WhoDoYouTrust/blob/main/applied-analysis/Why%20Delegations.md))

I have also written a separate document on **KCD** and **RBCD**, which can be found at [Constrained Delegation With Or Without PT](https://github.com/R3x5/WhoDoYouTrust/blob/main/applied-analysis/Constrained%20Delegation%20With%20Or%20Without%20PT.md)

In this section, I will analyze **KCD** and **RBCD**.

---

## 🔒 Kerberos Constrained Delegation (KCD)

KCD can be understood as **two consecutive TGS exchanges**—this is the essential nature of KCD.

Let's define a situation first:

```C
User (Alice)
   |
   v
WEB01 (IIS / Web App)
   |
   v
SQL01 (MSSQL)
```

And you may see configurations like this:

```C
Account: WEB01$
Trusted to delegate to:
  MSSQLSvc/SQL01.domain.local
```
### First TGS: S4U2Self

In the first step, **S4U2Self**, service **A (WEB01)** declares to the KDC that it intends to act on behalf of **Alice** in order to access service **B (MSSQL)**, specifically the service principal  
`MSSQLSvc/SQL01.domain.local`.

```C
TGS_REQ {
    sname = "HTTP/WEB01.domain.local",
    impersonated_user = "Alice@domain.local",
    flags = S4U2Self
}
```

```C
if (service_account == WEB01 && user_exists("Alice")) {
    issue ST_HTTP_WEB01_for_Alice;
}
```

At this point, **WEB01 does not possess Alice’s TGT or her session key**. It holds only its own service identity. The KDC then issues a **forwardable service ticket** to WEB01 that can be used to assert Alice’s identity. However, this ticket is for **Alice → WEB01** and **cannot be used directly to access SQL01**.

### Second TGS: S4U2Proxy

This leads to the second step, **S4U2Proxy**. WEB01 uses the **Alice → WEB01** service ticket to request a new ticket for **Alice → SQL01**. Because WEB01 is marked with the **`TRUSTED_TO_DELEGATE_TO`** attribute, the requested target service is explicitly allowed for delegation, and the user **Alice** exists, the KDC issues the requested ticket.

```C
TGS_REQ {
    ticket = ST_HTTP_WEB01_for_Alice,
    sname  = "MSSQLSvc/SQL01.domain.local"
}
```

```C
if (ticket.client == "Alice" && service_account == WEB01 && WEB01 is allowed to delegate to MSSQLSvc/SQL01) {
    issue ST_MSSQL_SQL01_for_Alice;
}
```

Finally, an **AP-REQ** is sent to SQL01. From SQL01’s perspective, it sees **Alice** accessing the service using a **legitimate service ticket issued by the KDC**. Throughout this entire process, **SQL01 is never aware of WEB01’s existence**.

If an attacker holds certain privileges on **WEB01** (such as **GenericWrite** or **WriteProperty**), they may be able, during the **S4U2Self** phase, to replace the _impersonated user_ with **any existing user**. However, this constitutes **only an identity assertion**, not an immediate acquisition of privileges. Much like the PAC in the AS phase, the _final authority_ over permissions resides in the **TGS phase**.

Another critical point to emphasize is that the _impersonated user_ does **not** equate to actual effective privileges. It merely determines **the source from which the PAC is derived**; the real authorization semantics are encoded within the PAC itself. Consequently, even if a high-privilege user is impersonated during the S4U2Self phase, if the PAC is subsequently replaced or constrained to a low-privilege PAC when the service ticket is generated, the target service can grant **only low-privilege access**.


## 🧩 Resource-Based Constrained Delegation (RBCD)

In **RBCD**, the **S4U2Self** phase is identical to that of KCD; the divergence occurs in the **S4U2Proxy** phase.

When **WEB01** contacts the KDC, it presents the ticket obtained during **S4U2Self**. 

```C
TGS_REQ {
    ticket = ST_HTTP_WEB01_for_Alice,
    sname  = CIFS/FILE01
}
```

At this point, the KDC evaluates whether **FILE01’s** `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute contains **WEB01**. The outcome depends solely on whether WEB01 is present in this attribute, and **does not depend on any other factors**, such as whether WEB01 itself possesses delegation privileges.

```C
if (FILE01.msDS-AllowedToActOnBehalfOfOtherIdentity contains WEB01) {
    issue ST(CIFS/FILE01, client=Administrator);
}
```

