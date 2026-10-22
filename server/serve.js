// server/serve.js — on-the-fly HTTPS server (Bun >= 1.4.3): no sites/, no signing step.
// The CA material (the recovered scalar-4 key) is loaded into memory once; every
// SNI that arrives gets a leaf minted at handshake time. Certificates exist only
// in this process's memory — nothing certificate-shaped is ever written to disk.
// Same server pattern as before: Bun.serve/node:https break SNI on Bun, node:tls
// SNICallback works — tls.createServer feeds a non-listening http server.
// Usage: bun server/serve.js     (PORT=4000, CHAIN=ecc|aaa)
import "reflect-metadata"; // required by the DI container (tsyringe) inside @peculiar/x509
import { readFileSync } from "node:fs";
import tls from "node:tls";
import http from "node:http";
import {
  cryptoProvider, X509Certificate, X509CertificateGenerator,
  BasicConstraintsExtension, ExtendedKeyUsageExtension, ExtendedKeyUsage,
  KeyUsageFlags, KeyUsagesExtension, SubjectAlternativeNameExtension,
  SubjectKeyIdentifierExtension, AuthorityKeyIdentifierExtension,
} from "@peculiar/x509";

cryptoProvider.set(crypto);

const stock = new URL("../stock/", import.meta.url).pathname;
const port = Number(process.env.PORT ?? 4000);
const pem = (der, label) =>
  `-----BEGIN ${label}-----\n${Buffer.from(der).toString("base64").match(/.{1,64}/g).join("\n")}\n-----END ${label}-----`;
const dearmor = (armor) => Buffer.from(armor.toString().replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");

const caCert = new X509Certificate(new Uint8Array(readFileSync(stock + "EMOVTLSCAG3C.crt"))); // .crt is DER
const caKey = await crypto.subtle.importKey(
  "pkcs8", dearmor(readFileSync(stock + "EMOVTLSCAG3C.key")),
  { name: "ECDSA", namedCurve: "P-384" }, false, ["sign"],
);

// CHAIN=ecc|aaa: which cross-signed card of the CA to send above the minted leaf
//   ecc — via emSign ECC Root CA - G3 (preinstalled on macOS/vivo/HarmonyOS/Pixel)
//   aaa — via Comodo AAA (older root, but Comodo revoked this cert cACompromise)
const chain = process.env.CHAIN ?? "ecc";
const intermediate = chain === "aaa"
  ? readFileSync(stock + "G3C-cross-signed-by-AAA.pem", "utf8")
  : readFileSync(stock + "G3-cross-by-ECCG3.pem", "utf8") + "\n" + readFileSync(stock + "EMOVTLSCAG3C.pem", "utf8");

// hostname → SecureContext, minted on first sight and reused for the process
// lifetime (a browser opens many connections; re-minting per TCP handshake
// would only burn CPU and rotate serials for nothing)
const minted = new Map();

const mintLeaf = async (san) => {
  const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const leaf = await X509CertificateGenerator.create({
    serialNumber: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("hex"),
    subject: `CN=${san[0].value}`,
    issuer: caCert.subject, // Issuer = CA's Subject: this is where the chain attaches
    publicKey: keys.publicKey,
    signingKey: caKey, // the CA stamp — the entire "acting as a CA" part
    signingAlgorithm: { name: "ECDSA", hash: "SHA-384" }, // match the family's ecdsa-with-SHA384
    notBefore: new Date(),
    notAfter: new Date(Date.now() + 199 * 86400e3), // CA/B Forum ≤200 days (Chromium: ERR_CERT_VALIDITY_TOO_LONG)
    extensions: [
      new BasicConstraintsExtension(false, undefined, false), // leaf: not a CA
      new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true), // ECDSA handshake only needs signing
      new ExtendedKeyUsageExtension([ExtendedKeyUsage.serverAuth, ExtendedKeyUsage.clientAuth]),
      new SubjectAlternativeNameExtension(san), // browsers match the name here
      await SubjectKeyIdentifierExtension.create(keys.publicKey),
      await AuthorityKeyIdentifierExtension.create(caCert.publicKey), // issuer's key fingerprint
    ],
  });
  return {
    key: pem(await crypto.subtle.exportKey("pkcs8", keys.privateKey), "PRIVATE KEY"),
    cert: leaf.toString("pem") + "\n" + intermediate, // leaf first, then the CA chain above it
  };
};
const mint = async (host) => tls.createSecureContext(await mintLeaf([{ type: "dns", value: host }]));

// the no-SNI fallback: clients hitting the IP directly (SNI carries no IPs) —
// cover both localhost and 127.0.0.1 so curl https://127.0.0.1:4000/ also matches
const defaultCreds = await mintLeaf([{ type: "dns", value: "localhost" }, { type: "ip", value: "127.0.0.1" }]);

// HTTP layer: listens on nothing; receives decrypted sockets from the TLS layer
const httpServer = http.createServer((req, res) => {
  const host = (req.headers.host ?? "").split(":")[0];
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  res.end(`<!doctype html><meta charset="utf-8"><body style="font-family:system-ui;max-width:36rem;margin:4rem auto;line-height:1.8">
<h1>${host}</h1>
<p>Certificate minted in memory for this name (chain: <code>${chain}</code>), stamped by the recovered key. Nothing on disk.</p>
<p><code>${req.method} ${req.url}</code></p>
</body>`);
});

// TLS layer: mint-or-reuse per SNI; refuse garbage names instead of signing junk
tls.createServer({
  ...defaultCreds, // fallback for clients that send no SNI
  SNICallback: (servername, cb) => {
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i.test(servername))
      return cb(new Error(`not a hostname: ${servername}`));
    const ctx = minted.get(servername);
    if (ctx) return cb(null, ctx);
    mint(servername).then((c) => (minted.set(servername, c), cb(null, c)), cb);
  },
}, (socket) => httpServer.emit("connection", socket)
).listen(port, () => {
  console.log(`https://127.0.0.1:${port} · any hostname minted on the fly (chain: ${chain})`);
  console.log(`try: curl --resolve whatever.example.org:${port}:127.0.0.1 https://whatever.example.org:${port}/`);
});
