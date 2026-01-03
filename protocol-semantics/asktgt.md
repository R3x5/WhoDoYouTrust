The `asktgt` operation represents the canonical execution of the Kerberos Authentication Service exchange from the client’s perspective.

Rather than bypassing authentication, it fulfills the protocol’s intended requirement: the client must demonstrate knowledge of the user’s long-term key before the KDC is willing to issue initial credentials.

In the `asktgt`technique, the AS-REQ phase is highly similar to that of [asreproasting](https://github.com/R3x5/WhoDoYouTrust/blob/main/protocol-semantics/asreproasting.md). The critical distinction is that `asktgt`provides `PA_DATA`.

```C
AS_REQ req;

req.pvno     = 5;
req.msg_type = AS_REQ;
req.cname    = "victim_user";
req.realm    = "DOMAIN.LOCAL";
req.sname    = "krbtgt/DOMAIN.LOCAL";

/* provide pre-auth */
req.pa_data = [
    type = PA_ENC_TIMESTAMP {
	    value = Encrypt (
		    key = user_long_term_key,
		    plaintext = current_timestamp
        )
    },
    PA_PAC_REQUEST { include_pac = true }
];

/* req-body */
kdc-options = FORWARDABLE | RENEWABLE | ...
nonce       = random
till        = timestamp
etype[]     = [aes256 / aes128 / rc4 ...]
nonce       = random();
etype       = { AES256, AES128, RC4 };

send_to_kdc(req);
```

When the KDC receives the AS-REQ, it first checks whether pre-authentication is required.

```C
user = lookup_account(req.cname, req.realm);

if (!user.exists) {
    reject;
}
if (user.requires_preauth) {
    goto normal_case;
} else {
	goto abnormal_case;
}
```

### Normal Scenario:​ 
The KDC finds that the account has pre-authentication enabled, examines the `PA_DATA`, and confirms the presence of `PA_ENC_TIMESTAMP`. The KDC then decrypts this timestamp using the user's long-term key stored in the domain. If the decryption succeeds and the timestamp is valid, the KDC legitimately generates and returns the AS-REP, as the pre-authentication has passed.

We can observe the general flow through the following pseudocode:

```C
if (user.requires_preauth == true) {
	/* 
	 The asktgt process should succeed at this step because the
	 client proactively provides the required data.
	*/
	pa_ts = find(req.pa_data, PA_ENC_TIMESTAMP);
	if (!pa_ts) {
		reject;
	}
	
	
    if (!verify_pa_enc_timestamp(req.pa_data, user.key)) {
        return PREAUTH_FAILED;
    }
    plaintext_ts = Decrypt(
	    key = user.long_term_key,
	    cipher = pa_ts.value
	);
    if (!plaintext_ts.valid || !within_clock_skew(plaintext_ts)) {
        reject;
    }
	/*
	 After the KDC completes this verification, it reaches a conclusion: the client
	 indeed possesses the user's long-term key. Subsequently, it generates the 
	 AS-REP. This constitutes "credential issuance" that occurs after "identity 
	 establishment"
	*/
	
	   /* Identity is now established */
	
/* Credential issuance (only reachable after identity establishment) */
return AS_REP;
```

**In contrast to AS-REP Roasting, where the KDC issues an AS-REP without prior identity establishment, the `asktgt` operation strictly enforces the Kerberos authentication semantics.**

**The presence and successful verification of `PA-ENC-TIMESTAMP` ensures that the AS-REP is generated only after the client’s possession of the long-term key has been cryptographically proven.**

### Abnormal Scenario: 
This appears very similar to AS-REP Roasting but differs in semantics. The KDC determines that the account does _not_ require pre-authentication. Therefore, even if `PA_DATA`is provided, the KDC may choose to ignore it and return an AS-REP.

```C
if (user.requires_preauth == false) {
    /* it does not REQUIRE proof of possession before issuing AS-REP */
    return AS_REP;
}
```

Only _after_ "identity establishment" does the KDC generate the session key and TGT, and construct the AS-REP. This step implies that the client must once again prove its possession of the user's long-term key to decrypt the `enc_part`and obtain the session key. This is Kerberos's dual-verification design.

```C
EncASRepPart enc_part_plain;

enc_part_plain.session_key = random_key();
enc_part_plain.authtime    = now();
enc_part_plain.starttime   = now();
enc_part_plain.endtime     = now() + TGT_LIFETIME;
enc_part_plain.flags       = DEFAULT_FLAGS;
enc_part_plain.sname       = krbtgt/REALM;

/* encrypt EncASRepPart with the key derived from user's password */
Key user_long_term_key = user.stored_kerberos_key;

EncryptedData enc_part;
enc_part.etype  = user.etype;
enc_part.cipher = encrypt(
    key  = user_long_term_key,
    data = enc_part_plain
);

/* generate TGT (encrypted with krbtgt key) */
Ticket tgt = Encrypt(
    key  = krbtgt_key,
    data = Ticket {
        session_key,
        user,
        realm,
        flags,
        times
    }
);

/* construct AS-REP */
AS_REP as_rep;

// as_rep.cname  = user.name;
// as_rep....   // optional / omitted for brevity
as_rep.ticket   = tgt;
as_rep.enc_part = enc_part;

/* return AS-REP to client */
send_to_client(as_rep);

return AS_REP;
```

Finally, the client completes the `asktgt`operation. At this point, the KDC has confirmed your identity, and you have obtained the KDC-issued TGT, formally concluding the AS (Authentication Service) stage of Kerberos.

```C
AS_REP rep = recv_from_kdc();

enc_part = rep.enc_part;

plaintext  = Decrypt(
    key    = user_long_term_key,
    cipher = enc_part
);

if (!plaintext.valid)
    authentication_failed;

/* get TGT */
TGT = rep.ticket;
```

It is worth noting that the KDC in normal case generates the AS-REP—which contains the `EncASRepPart`encrypted with the user's long-term key and the TGT encrypted with the `krbtgt`key—after successfully decrypting and validating the timestamp's freshness. In contrast, when pre-authentication is _not_ enabled, the KDC generates the AS-REP without establishing prior possession of the user's long-term key.

#### Now we can conclude:

**The `asktgt`operation essentially represents the standard execution flow of the Kerberos Authentication Service protocol. The client proves its possession of the user's long-term key to the KDC by providing a `PA-ENC-TIMESTAMP`encrypted with that same key within the AS-REQ.**

**After confirming that the account requires pre-authentication, the KDC uses the stored user's long-term key to decrypt and validate the timestamp. A successful verification establishes the client's identity, after which the KDC generates and returns the AS-REP containing the TGT.**

**Therefore, in normal case, `asktgt`does not circumvent authentication; rather, it is a complete and strict implementation adhering to the intended authentication semantics of Kerberos.**
