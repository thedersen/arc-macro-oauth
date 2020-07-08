@app
auth0

@aws
region eu-central-1
apigateway http

@oauth
permissionClaim https://jwt.example.no/permissions
permissions access:admin
domain aaks.eu.auth0.com
audience https://*-api.example.no
scope "openid profile email"
staging
  callbackUrl https://o4qjrk73ha.execute-api.eu-central-1.amazonaws.com/auth/callback
  logoutRedirect /
  errorRedirect /

@http
get /
get /secure
get /secure/:foo

@macros
arc-macro-oauth
