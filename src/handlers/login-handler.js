const {http} = require('./login-handler-deps');
const {handler: originalHandler} = require('.');

exports.handler = async function (request, context) {
  // Payload v2 fix
  if (request.cookies) {
    request.headers.cookie = request.cookies.join(';');
  }

  const session = await http.session.read(request);

  if (session.expires > new Date().getTime() && session.id) {
    if (process.env.LOGIN_PERMISSIONS) {
      const requiredPermissions = process.env.LOGIN_PERMISSIONS.split(',');
      const assignedPermissions = session.id[process.env.PERMISSION_CLAIM];

      const hasAccess = assignedPermissions.some((p) =>
        requiredPermissions.includes(p)
      );

      if (!hasAccess) {
        return {
          statusCode: 403,
          headers: {
            'Content-Type': 'text/html; charset=UTF-8',
          },
          body: 'Access Denied',
        };
      }
    }

    request.session = session;
    const response = await originalHandler(request, context);
    response.headers['Cache-Control'] = 'no-store';
    return response;
  }

  return {
    statusCode: 302,
    headers: {
      Location: `/auth/login?continue_to=${request.rawPath}`,
    },
  };
};
