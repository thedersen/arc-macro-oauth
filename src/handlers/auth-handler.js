const {qs, fetch, jwksClient, jwt, http} = require('./auth-handler-deps');

function verifyToken(token, options) {
  const {algorithms = ['RS256'], audience, issuer} = options;

  const client = jwksClient({
    jwksUri: new URL('/.well-known/jwks.json', issuer),
  });

  const getKey = (header, callback) => {
    client.getSigningKey(header.kid, (err, key) => {
      const signingKey = key.publicKey || key.rsaPublicKey;
      callback(err, signingKey);
    });
  };

  return new Promise((resolve, reject) => {
    const jwtOptions = {
      algorithms,
      audience,
      issuer,
    };

    jwt.verify(token, getKey, jwtOptions, (err, decoded) => {
      if (err) {
        reject(err);
      } else {
        resolve(decoded);
      }
    });
  });
}

async function login(request, options) {
  const queryStringParameters = request.queryStringParameters || {};
  const {clientId, callbackUrl, connection, audience, domain, scope} = options;
  const continueTo = queryStringParameters.continue_to;

  const q = qs.stringify({
    client_id: clientId, // eslint-disable-line camelcase
    redirect_uri: callbackUrl, // eslint-disable-line camelcase
    response_type: 'code', // eslint-disable-line camelcase
    scope,
    connection,
    audience,
  });

  // Payload v2
  if (request.cookies) {
    request.headers.cookie = request.cookies.join(';');
  }

  const session = await http.session.read(request);
  session.continueTo = continueTo;
  const cookie = await http.session.write(session);

  return {
    statusCode: 302,
    headers: {
      Location: `https://${domain}/authorize?${q}`,
      'Set-Cookie': cookie,
    },
  };
}

async function logout(request, options) {
  const {logoutRedirect} = options;
  // Payload v2
  if (request.cookies) {
    request.headers.cookie = request.cookies.join(';');
  }

  const session = await http.session.read(request);

  delete session.expires;
  delete session.accessToken;
  delete session.id;

  const cookie = await http.session.write(session);

  return {
    statusCode: 302,
    headers: {
      Location: logoutRedirect,
      'Set-Cookie': cookie,
    },
  };
}

async function callback(request, options) {
  const queryStringParameters = request.queryStringParameters || {};
  const {clientId, clientSecret, callbackUrl, domain, errorRedirect} = options;

  if (queryStringParameters.error) {
    return {
      statusCode: 302,
      headers: {
        Location: `${errorRedirect}?error=${queryStringParameters.error}&error_description=${queryStringParameters.error_description}`,
      },
    };
  }

  const tokens = await fetch(`https://${domain}/oauth/token`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      grant_type: 'authorization_code', // eslint-disable-line camelcase
      code: queryStringParameters.code,
      client_id: clientId, // eslint-disable-line camelcase
      client_secret: clientSecret, // eslint-disable-line camelcase
      redirect_uri: callbackUrl, // eslint-disable-line camelcase
    }),
  }).then((response) => response.json());

  const id = await verifyToken(tokens.id_token, {
    audience: clientId,
    issuer: `https://${domain}/`,
  });

  // Payload v2
  if (request.cookies) {
    request.headers.cookie = request.cookies.join(';');
  }

  const {continueTo, ...session} = await http.session.read(request);

  // Expire session with access_token
  // JWTs uses seconds, cookies milliseconds
  const maxAge = tokens.expires_in * 1000;
  process.env.SESSION_TTL = tokens.expires_in;
  session.expires = new Date(Date.now() + maxAge).getTime();
  session.accessToken = tokens.access_token;
  session.id = id;

  const cookie = await http.session.write(session);

  return {
    statusCode: 302,
    headers: {
      Location: continueTo || '/',
      'Set-Cookie': cookie,
    },
  };
}

async function getSession(request) {
  const session = await http.session.read(request);
  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(session),
  };
}

function handler(options) {
  return async function (request) {
    switch (request.pathParameters.path) {
      case 'login':
        return login(request, options);
      case 'logout':
        return logout(request, options);
      case 'callback':
        return callback(request, options);
      case 'session':
        return getSession(request);
      default:
        return {
          statusCode: 404,
          body: 'Not Found',
        };
    }
  };
}

exports.handler = handler({
  domain: process.env.OAUTH_DOMAIN,
  clientId: process.env.OAUTH_CLIENT_ID,
  clientSecret: process.env.OAUTH_CLIENT_SECRET,
  scope: process.env.OAUTH_SCOPE || 'openid profile email',
  audience: process.env.OAUTH_AUDIENCE,
  callbackUrl: process.env.OAUTH_CALLBACK_URL,
  logoutRedirect: process.env.OAUTH_LOGOUT_REDIRECT || '/',
  errorRedirect: process.env.OAUTH_ERROR_REDIRECT || '/',
});
