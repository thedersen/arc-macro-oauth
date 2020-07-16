const parse = require('@architect/parser');
const fs = require('fs');
const {copySync} = require('fs-extra');
const path = require('path');

module.exports = function (arc, cfn, stage) {
  if (!arc.oauth) {
    return cfn;
  }

  const apiName = getApiName(cfn);
  const config = getConfig(arc, stage);

  if (config === false) {
    return cfn;
  }

  const {GetIndex} = cfn.Resources;
  cfn.Resources.GetOAuth = {
    Type: 'AWS::Serverless::Function',
    Properties: {
      Handler: 'index.handler',
      CodeUri: './node_modules/arc-macro-oauth/dist/auth-handler',
      Runtime: 'nodejs12.x',
      MemorySize: 512,
      Timeout: 5,
      Environment: {
        Variables: {
          ...GetIndex.Properties.Environment.Variables,
          OAUTH_DOMAIN: config.domain,
          OAUTH_AUDIENCE: config.audience,
          OAUTH_SCOPE: config.scope,
          OAUTH_CALLBACK_URL: config.callbackUrl,
          OAUTH_LOGOUT_REDIRECT: config.logoutRedirect,
          OAUTH_ERROR_REDIRECT: config.errorRedirect,
        },
      },
      Role: GetIndex.Properties.Role,
      Events: {
        GetLoginEvent: {
          Type: 'HttpApi',
          Properties: {
            Path: '/auth/{path}',
            Method: 'GET',
            ApiId: {
              Ref: apiName,
            },
          },
        },
      },
    },
  };

  for (const resource of findRoutes(cfn)) {
    const pathToCode = cfn.Resources[resource].Properties.CodeUri;
    const routeConfig = getRouteConfig(pathToCode);

    if (routeConfig !== false || config.default) {
      const folder = pathToCode.split('/').pop();
      const dest = `./.build/arc/${folder}`;
      fs.rmdirSync(dest, {recursive: true});
      fs.mkdirSync(dest, {recursive: true});
      copySync(pathToCode, dest);
      copySync(
        './node_modules/arc-macro-oauth/dist/login-handler/login-handler-deps/index.js',
        `${dest}/login-handler-deps/index.js`
      );
      copySync(
        './node_modules/arc-macro-oauth/dist/login-handler/index.js',
        `${dest}/login-handler.js`
      );

      const properties = cfn.Resources[resource].Properties;
      properties.Handler = 'login-handler.handler';
      properties.CodeUri = dest;
      properties.Environment.Variables.PERMISSION_CLAIM =
        config.permissionClaim;
      if (config.default) {
        properties.Environment.Variables.LOGIN_PERMISSIONS = config.permissions;
      } else {
        properties.Environment.Variables.LOGIN_PERMISSIONS =
          routeConfig.permissions || config.permissions;
      }
    }
  }

  return cfn;
};

function getApiName(cfn) {
  return Object.keys(cfn.Resources).find(
    (resource) => cfn.Resources[resource].Type === 'AWS::Serverless::HttpApi'
  );
}

function findRoutes(cfn) {
  function isFunction(resource) {
    return resource.Type === 'AWS::Serverless::Function';
  }

  function hasHttpEvent(resource, name) {
    return (
      resource.Properties &&
      resource.Properties.Events &&
      Object.keys(resource.Properties.Events).length > 0 &&
      Object.keys(resource.Properties.Events).includes(`${name}Event`) &&
      resource.Properties.Events[`${name}Event`].Type === 'HttpApi'
    );
  }

  return Object.keys(cfn.Resources)
    .filter((resource) => isFunction(cfn.Resources[resource]))
    .filter((resource) => hasHttpEvent(cfn.Resources[resource], resource));
}

function getConfig(arc, stage) {
  const defaultConfig = {
    default: false,
    permissionClaim: '',
    permissions: '',
    domain: '',
    audience: '',
    scope: 'openid profile email',
    callbackUrl: '',
    logoutRedirect: '/',
    errorRedirect: '/',
  };
  // From:
  // [
  //   [
  //     'permissionClaim',
  //     '...'
  //   ],
  //   {
  //     staging: {
  //        ...
  //     }
  //   }
  // ]
  // To:
  // [
  //   [
  //     'permissionClaim',
  //     '...'
  //   ],
  //   [
  //     'staging',
  //     {
  //       ...
  //     }
  //   ]
  // ]
  function toEntry(entry) {
    if (!Array.isArray(entry)) {
      return Object.entries(entry)[0];
    }

    return entry;
  }

  const entries = arc.oauth.map((o) => toEntry(o));
  // To:
  // {
  //   permissionClaim: 'https://jwt.alesundkristnesenter.no/permissions',
  //   staging: {
  //     ...
  //   }
  // }
  const config = Object.fromEntries(entries);
  if (!config[stage]) {
    return false;
  }

  return {
    ...defaultConfig,
    ...config,
    ...config[stage],
  };
}

function getRouteConfig(pathToCode) {
  const defaultConfig = {
    permissions: '',
  };
  const arcFile = path.join(pathToCode, '.arc-config');
  const exists = fs.existsSync(arcFile);

  if (exists) {
    const raw = fs.readFileSync(arcFile).toString().trim();
    const config = parse(raw);

    if (config.oauth) {
      return {
        ...defaultConfig,
        ...Object.fromEntries(config.oauth),
      };
    }
  }

  return false;
}
