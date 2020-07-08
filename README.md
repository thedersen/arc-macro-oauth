# arc-macro-oauth

Use OAuth authentication with [Architect](https://arc.codes) HTTP APIs (APIG HTTP Api only).

### Install:

`npm i arc-macro-oauth`

Add to your .arc-file:

```arc
@app
myapp

@aws
apigateway http

@oauth
default true #Secure all routes by default
permissionClaim https://jwt.example.no/permissions #Specify name of permission claim in ID token
permissions access:admin,access:site #Default permissions needed (remove for none)
domain example.auth0.com #OAuth issuer domain
audience https://example.com #OAuth audience
scope "openid profile email" #OAuth authorization scope
logoutRedirect / #Redirect to after logout
errorRedirect / #Redirect to on error
staging
  callbackUrl https://staging.example.com/auth/callback #OAuth callback url for staging
production
  callbackUrl https://example.com/auth/callback #OAuth callback url for production

@http
get /
get /secure

@macros
arc-macro-oauth
```

And add to individual .arc-config files for routes that needs auth:

```arc
@oauth
permissions access:foo,access:bar #Not required (use default permissions or none when not specified)
```
Finally, add environment variables:

```
arc env [staging/production] OAUTH_CLIENT_ID xxxxxxxxxxxxxxxx
arc env [staging/production] OAUTH_CLIENT_SECRET xxxxxxxxxxxxxxxxxxxxxx
arc env [staging/production] ARC_APP_SECRET xxxxxxxxxxxxxxxxxxxxxx
```
See [AWS::Serverless::HttpApi/HttpApiAuth](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-httpapi-httpapiauth.html) for more information.
