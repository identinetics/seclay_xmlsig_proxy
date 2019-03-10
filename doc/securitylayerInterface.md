# Security Layer Interface hints

##  Command-Line test

Write POST reqeust contents (not encoded) to a file and pipe it into:

    cat tests/testdata/seclay_createsig_preenc_ok.request | curl -v --data "@-" http://127.0.0.1:13495/http-security-layer-request  
    # or
    curl -v --data @tests/testdata/seclay_createsig_preenc_ok.request http://127.0.0.1:13495/http-security-layer-request



Example file: tests/testdata/ seclay_createsig_ok.request


## Problem Handling

Security Layer returns HTTP Code 200 and an Error XMl document when a signature request is not successful.

Multiple failed signature request may either crash MOCCA or cause repeated eeror responses.

Security Layer Code 2000 ("unknown transport binding") may be cause by a character encoding issue.

