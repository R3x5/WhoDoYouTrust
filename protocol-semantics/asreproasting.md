1. In a standard authentication process, you declare to the system, "I am `Alice`."

2. The system then prompts you to provide verification to prove that you are indeed `Alice`.

3. You subsequently perform a cryptographic or authentication action, using your password, that the system can validate.

4. Once the system confirms your identity as `Alice`, it grants you access to `Alice`'s resources.

If you cannot provide the correct password, the process fails at step 2. The system will not proceed further and will not disclose any sensitive information.

```C
AS_REQ req;

req.pvno      = 5;
req.msg_type  = AS_REQ;
req.cname     = "victim_user";
req.realm     = "DOMAIN.LOCAL";
req.sname     = "krbtgt/DOMAIN.LOCAL";

req.pa_data = []; // empty PA-DATA list

/* req-body */
kdc-options = FORWARDABLE | RENEWABLE | ...
nonce       = random
till        = timestamp
etype[]     = [aes256 / aes128 / rc4 ...]
nonce       = random();
etype       = { AES256, AES128, RC4 };

send_to_kdc(req);
```

In an abnormal scenario, as when an account has Pre-Authentication disabled, the process unfolds as follows:

1. You declare to the system, "I am `Alice`."

2. The system checks the account configuration and finds that prior password verification is not required.

3. Consequently, the system directly hands you a locked box belonging to `Alice`.

This box and its lock are both cryptographically valid. The key to opening it is `Alice`'s password. The system's design intends that only the genuine `Alice`can open it, but it has now granted you the box without verifying your identity. Thereafter, you can take this box offline and attempt to brute-force the password at your own pace to open it.

```C
/* Identity Declaration (no proof yet) */
user = lookup_user(req.cname);

if (user.requires_preauth) {
 /* Proof of Key Possession REQUIRED */
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
	if (!plaintext_ts.valid) {
	    reject;
	}
	if (!within_clock_skew(plaintext_ts))
	    reject;
	}
}

	/* more details about this step, see ASKTGT */

/* Successfully. Credential Issuance */
return AS_REP;
```


```C
if (user.requires_preauth == false) {
    /* it does not REQUIRE proof of possession before issuing AS-REP */
    return AS_REP;
}
```


```C
/* generate EncASRepPart contents */
EncASRepPart enc_part_plain;

enc_part_plain.session_key = random_key();
enc_part_plain.authtime    = now();
enc_part_plain.starttime   = now();
enc_part_plain.endtime     = now() + TGT_LIFETIME;
enc_part_plain.flags       = DEFAULT_FLAGS;
enc_part_plain.sname       = krbtgt/REALM;

/* encrypt EncASRepPart with the key derived from user's  */
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


```C
AS_REP rep = recv_from_kdc();

/* ticket? I don't care */
EncryptedData roast_me = rep.enc_part;
```

#### Summary
So, let's describe these steps in more professional terms:

In AS-REP Roasting, the Key Distribution Center (KDC) first checks whether pre-authentication is enabled (as is the case for any AS-Exchange).

If it is enabled, the KDC checks for `PA_ENC_TIMESTAMP`within the `PA_DATA`. Since the `PA_DATA`in the request is empty, the KDC returns a `PREAUTH_REQUIRED`error, and the process fails.

If pre-authentication is _not_ enabled, the KDC skips the `PA_DATA`check. It proceeds to return an `AS-REP`message, which is encrypted using a key derived from the user's password.

**From a security-model perspective, AS-REP Roasting does _not_ exploit a cryptographic weakness in Kerberos. Instead, it exploits a relaxation of the authentication boundary at the Authentication Service stage.**
