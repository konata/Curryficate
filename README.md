# Curryficate

*to curry-ficate (v.): to issue certificates with a compromised CA.*

A CA leaked its private key. The key turned out to be the integer **4**.
This is the lab where that key went back to work.

```
bun server/serve.js
curl --resolve anything.example:4000:127.0.0.1 https://anything.example:4000/   # green
```

That's the whole product. The server holds the recovered CA key in memory and
mints a fresh leaf for every hostname it has never seen — certs never touch
disk. `CHAIN=aaa|ecc` picks which cross-signed ID card to present above the
leaf; the CA material lives in `stock/`.
