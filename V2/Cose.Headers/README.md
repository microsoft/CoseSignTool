# Cose.Headers

Generic COSE header implementations independent of any specific COSE message type.

## Contents
- `CwtClaims` — CWT Claims model (RFC 8392): iss, sub, aud, exp, nbf, iat, cti
- `CwtClaimsHeaderContributor` — Virtual base for contributing CWT claims to COSE headers
- `CWTClaimsHeaderLabels` — CWT claim label constants
- `CoseHeaderMapCwtClaimsExtensions` — Extension methods for CWT claims on CoseHeaderMap
