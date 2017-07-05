# Gimli constructions

Cross-platform cryptographic constructions and implementations based on the
[Gimli permutation](https://gimli.cr.yp.to),
with a [Hydrogen](https://github.com/jedisct1/libhydrogen/wiki)-inspired API.

These implementations are portable across a wide range of platforms, including
big-endian architectures.

This is a work in progress.

## Generic hashing

The construction used for generic hashing is similar to the NIST SP
800-185 KMAC construction, leveraging the Gimli hash function instead
of cSHAKE.

```
H(pad(str_enc("kmac") || str_enc(context)) || pad(str_enc(k)) ||
  msg || right_enc(msg_len) || 0x00)
```

In order to encourage reasonable practices, this specific
implementation requires an optional key between 128 and 256 bits, and
a 8 bytes context. The output size can be up to 65535 bytes.

We also define a variant that extends KMAC to include a 64 bit tweak.

```
H(pad(str_enc("tmac") || str_enc(context)) || pad(str_enc(k)) ||
  pad(right_enc(tweak)) || msg || right_enc(msg_len) || 0x00)
```
