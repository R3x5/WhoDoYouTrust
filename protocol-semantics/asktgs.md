In the `asktgs`phase, the process is no longer about ***authentication*** but rather ***authorization*** plus ***credential derivation***. A critical prerequisite is that **_identity establishment_ is already complete**​ upon entering the TGS stage. This means that, within the protocol semantics, `asktgs`fully trusts the conclusion established during the AS phase.

More precisely, the TGS stage is concerned with maintaining the continuity of an already
authorized identity. Its primary security objective is not to determine *who* the client is,
but to ensure that any authorization decision is derived from an identity whose control
has not been interrupted since authentication.

## 📌 **Quote (RFC 4120 Section 1.1)**  
>    The basic Kerberos authentication process proceeds as follows: A
    client sends a request to the authentication server (AS) for
    "credentials" for a given server.  The AS responds with these
    credentials, encrypted in the client's key.  The credentials consist
    of a "ticket" for the server and a temporary encryption key (often
    called a "session key").  The client transmits the ticket (which
    contains the client's identity and a copy of the session key, all
    encrypted in the server's key) to the server.  The session key (now
    shared by the client and server) is used to authenticate the client
    and may optionally be used to authenticate the server.  It may also
    be used to encrypt further communication between the two parties or
    to exchange a separate sub-session key to be used to encrypt further
    communication.  Note that many applications use Kerberos' functions
    only upon the initiation of a stream-based network connection.
    Unless an application performs encryption or integrity protection for
    the data stream, the identity verification applies only to the
    initiation of the connection, and it does not guarantee that
    subsequent messages on the connection originate from the same
    principal.
    
    Link: https://datatracker.ietf.org/doc/html/rfc4120#section-1.1

Unlike the AS stage, when constructing the TGS-REQ, the client must provide the following information:

- A TGT that is recognized by the KDC.
    
- An Authenticator that serves as immediate proof that the client still possesses the established identity.
    
- A specific authorization target (SPN).

**All three components are indispensable, so I assert that:**

```
1. I possess a valid TGT issued by the KDC
2. I currently possess the session key bound to that TGT
3. I request access to service X under the constraints encoded in my TGT
```

These assertions are not mere claims. Each of them must be **independently** validated by the KDC using cryptographic material already bound to the established identity. Failure to validate any single assertion results in immediate rejection of the request.


> *For clarity, the following section first presents a complete TGS processing skeleton.*  
> *The analysis that follows focuses only on the security-critical checks within this flow.*

### TGS-REQ

```C
TGS_REQ req;

req.pvno     = 5;
req.msg_type = TGS_REQ;
req.realm    = "DOMAIN.LOCAL";
req.sname    = "HTTP/websrv.DOMAIN.LOCAL";
...            /* omitted */

/* provided ticket */
req.ticket = TGT;

/* authenticator */
req.authenticator = Encrypt(
    key = tgt_session_key,
    plaintext = {
        cname      = user.name,
        realm      = user.realm,
        timestamp  = now(),
        subkey     = optional,
        seq_number = optional
    }
);

/* req-body */
kdc-options = FORWARDABLE | RENEWABLE | ...
nonce       = random();
etype[]     = [aes256 / aes128 / rc4 ...];
...          /* omitted */

send_to_kdc(req);
```

**From a semantic perspective, the described code is equivalent to declaring: "I am attempting to request access to service X, and I still possess the TGT session key that you and I share."**


### Send To KDC

The core logic of the KDC upon receiving the TGS-REQ is as follows:

- The verification here is not of the user's password, but rather of whether the presented TGT was issued by the KDC itself.

```C
tgt_plain = Decrypt(
    key    = krbtgt_key,
    cipher = req.ticket
);

/* 
	This step does not verify the client's identity. Instead, it verifies the
	provenance of the ticket itself, confirming that the TGT was issued by this
	KDC and has not been tampered with.
*/

if (!tgt_plain.valid) {
    reject;
}
```

- This step confirms that the client indeed possesses the session key bound to this specific TGT. In other words, it verifies the continuity of the established identity and ensures the request is not a replay. 

- At this point, the KDC has not learned anything new about the client's identity. Instead, it has verified a single invariant: the entity making the request still controls the cryptographic material that was bound to the authenticated identity during the AS stage. All subsequent authorization decisions rely on this invariant remaining true.

## 📌 **Quote (RFC 4120 Section 1.1)**  
>    *To verify the identities of the principals in a transaction, the*
>    *client transmits the ticket to the application server.  Because the*
>    *ticket is sent "in the clear" (parts of it are encrypted, but this*
>    *encryption doesn't thwart replay) and might be intercepted and reused*
>    *by an attacker, additional information is sent to prove that the*
>    *message originated with the principal to whom the ticket was issued.*
>    *This information (called the authenticator) is encrypted in the*
>    *session key and includes a timestamp.  The timestamp proves that the*
>    *message was recently generated and is not a replay.  Encrypting the*
>    *authenticator in the session key proves that it was generated by a*
>    *party possessing the session key.  Since no one except the requesting*
>    *principal and the server know the session key (it is never sent over*
>    *the network in the clear), this guarantees the identity of the*
>    *client.*
>
>    **Link**: https://datatracker.ietf.org/doc/html/rfc4120#section-1.1

```C
auth_plain = Decrypt(
    key    = tgt_plain.session_key,
    cipher = req.authenticator
);

/* 
	By successfully decrypting and validating the authenticator using the TGT
	session key, the KDC confirms continuous control over the session key. This
	establishes temporal continuity of the previously authenticated identity
	rather than re-authentication.
*/

if (!auth_plain.valid) {
    reject;
}

if (!within_clock_skew(auth_plain.timestamp)) {
    reject;
}

if (is_replay(auth_plain)) {
    reject;
}
```

- This step represents the fundamental semantic divergence between`asktgs`and `asktgt`: the AS stage is concerned with establishing **"Who are you?"**, while the TGS stage is concerned with authorizing **"Can you have this?"**.

```C
service = lookup_service(req.sname, req.realm);

if (!service.exists) {
    reject;
}

if (!policy_allows(
        client  = tgt_plain.cname,
        service = service,
        flags   = tgt_plain.flags,
        options = req.kdc-options
    )) {
    reject;
}
```


### Build Service Ticket

Once all verifications and policy checks are satisfied, the KDC proceeds to perform credential issuance:

```C
/* generate service session key */
Key service_session_key = random_key();

/* construct EncTGSRepPart */
EncTGSRepPart enc_part_plain;

enc_part_plain.session_key = service_session_key;
enc_part_plain.client      = tgt_plain.cname;
enc_part_plain.flags       = derived_flags;
enc_part_plain.authtime    = tgt_plain.authtime;
enc_part_plain.starttime   = now();
enc_part_plain.endtime     = now() + SERVICE_TICKET_LIFETIME;
enc_part_plain.sname       = service.name;

/* encrypt enc-part for client */
EncryptedData enc_part;

enc_part.etype  = tgt_plain.session_key.etype;
enc_part.cipher = Encrypt(
    key  = tgt_plain.session_key,
    data = enc_part_plain
);
```


### Service Ticket

This is the key point of the capability-based design: the client cannot read the ticket's contents; it can only relay it to the service, and the service confirms authorization by decrypting the ticket.

The service ticket embodies Kerberos’s capability-based design. Possession of the ticket constitutes the capability itself. The client is not expected to understand or interpret the ticket’s contents; it merely acts as a secure carrier between the KDC and the target service.

**_Reference_** : https://www.geeksforgeeks.org/computer-networks/ticket-granting-server-tgs/

![img](/Images/Pasted%20image%2020260101201251.png)

```C
Ticket service_ticket = Encrypt(
    key  = service.long_term_key,
    data = {
        session_key = service_session_key,
        client      = tgt_plain.cname,
        realm       = tgt_plain.realm,
        flags,
        times
    }
);
```


### TGS-REP

```C
TGS_REP rep;

rep.ticket   = service_ticket;
rep.enc_part = enc_part;

send_to_client(rep);
```


### End Of `asktgs`

**The client obtains a KDC-explicitly authorized access capability that is strictly limited to a specified service.**

```C
TGS_REP rep = recv_from_kdc();

enc_part_plain = Decrypt(
    key    = tgt_session_key,
    cipher = rep.enc_part
);

if (!enc_part_plain.valid) {
    authentication_failed;
}

/* 
   client now holds:
   - service_ticket (opaque)
   - service_session_key
*/
```

`asktgs` does not re-establish identity. Instead, building upon an already established identity, it prevents credential transfer by verifying the immediate possession of the session key and, under policy constraints, creates a service-bound access capability. The security of the TGS stage relies not on the user's long-term key, but on the continuous control of the session key, thereby achieving the principles of least exposure and minimal trust propagation.

### Now let's compare the differences between `asktgs`and `asktgt`. Here is the process for `asktgs`:

*In the TGS-REQ stage, the client no longer provides `PA_DATA`because identity establishment was completed during the AS stage. The client proves it still controls the session key generated from that identity establishment by submitting a KDC-issued TGT and an authenticator encrypted with the TGT session key.*

*The KDC must successfully decrypt both the TGT (using the krbtgt key) and the authenticator (using the TGT session key) to confirm the legitimacy of the identity assertion and the continuity of control. Only if both conditions are met will the KDC proceed to authorization evaluation and derive the service ticket.*

*So, `asktgs` does not re-establish identity. It assumes identity continuity and enforces authorization by validating uninterrupted control over the session key. Under the constraints encoded in the TGT and domain policy, the KDC derives a service-bound access capability that minimizes trust propagation and prevents credential reuse across services.*

*The security of the TGS stage therefore relies not on the user's long-term secret, but on the ongoing possession of a short-lived session key, preserving least privilege while maintaining cryptographic continuity.*
