# Proxy Service to provide SecLayer XMl Signature

## Purpose

Request an XML infoset to be signed by a signing service not directly accessible from the client.
The connection to the signing service is via front-channel, that is via the browser.

Rationale: Provide a interface for convenient integration into an web application 
(here called the "external webapp").
It provides good separation of concerns with a small set of signature args:

1. Unsigned XML
2. XMLDsig structure (enveloping, enveloped SAML EntityDescriptor).
The "enveloped SAML EntityDescriptor" provides an implicit signature location.


## Flow

See doc/sequence_diagram.png

The interface (for an external web app) is implemented as a HTTP GET request 
and provides following arguments:

* unsigned XML
* Signature type (enveloping, samled)
* result_to  (path at the external web app to POST result to)
* return (path to finally redirect the browser at the external web app)


## Test setup:

1. start sig_proxy.py
2. start signature_service.py
3. start the external webapp (proxy or real) 
4. Trigger the folw at the external webapp


## Deployment

The SigProxy server should be deployed with an TLS-terminating proxy.
It can be proxied into the namespace of the external webapp; the root path can be rewritten, e.g.

http://sigproxy/SigProxy/xxx  -> http://sigproxy/nonappnamespace/xxx