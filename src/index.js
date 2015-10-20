import bodyParser from 'body-parser';
import httpProxy from 'http-proxy';
import request from 'request';
import session from 'express-session';
const RedisStore = require('connect-redis')(session);

const options = {
  jwtClientId: undefined,
  jwtClientSecret: undefined,
  tokenOverride: undefined,
  authenticationEndpoint: undefined,
  apiHost: undefined,
  apiPort: 80,
  apiPrefix: 'api',
  debug: false
};

let proxy = undefined;

function debug(...args) {
  if (options.debug) {
    console.log(args);
  }
}

function setupProxy(options) {
  proxy = httpProxy.createProxyServer({
    target: options.apiHost + ':' + options.apiPort,
    changeOrigin: true // otherwise heroku claims app doesn't exist: http://stackoverflow.com/a/6445766/583755
  });

  // https://github.com/nodejitsu/node-http-proxy/issues/839
  proxy.on('proxyReq', function (proxyReq, req, res) {
    const apiRequestPath = `/${options.apiPrefix}${proxyReq.path}`
    debug('api request, going to path: ', apiRequestPath);
    proxyReq.path = apiRequestPath;
  });

  // added the error handling to avoid https://github.com/nodejitsu/node-http-proxy/issues/527
  proxy.on('error', (error, req, res) => {
    let json;
    debug('proxy error', error);
    if (!res.headersSent) {
      res.writeHead(500, {'content-type': 'application/json'});
    }

    json = { error: 'proxy_error', reason: error.message };
    res.end(JSON.stringify(json));
  });
}

function configure(overrides) {
  for(const key in overrides) {
    options[key] = overrides[key]
  }
  debug('JWT Config options:', options);

  setupProxy(options);
}

function login(req, res) {
  const form = {
    grant_type: 'password',
    email: req.body.user.email,
    password: req.body.user.password
  }
  // client id and secret are not always required, only add if specified
  if (options.jwtClientId && options.jwtClientSecret) {
    form.jwtClientId = options.jwtClientId;
    form.jwtClientSecret = options.jwtClientSecret;
  }
  request({
    method: 'POST',
    url: options.authenticationEndpoint,
    form: form
  }, (error, response, body) => {
    response = JSON.parse(response.body);
    if(!error && response.access_token) {
      const token = response.access_token;
      debug('auth returned access token', token);
      req.session.token = token;
      req.session.save((err) => {
        if (err) {
          debug('error saving session', err);
        }
      });
      res.sendStatus(200);
    } else {
      debug('auth error', body);
      res.sendStatus(401);
    }
  });
}

function logout(req, res) {
  req.session.destroy((err) => {
    debug('error destroying session', err);
  });
  res.sendStatus(200);
}

function apiProxy(req, res) {
  if(req.session.token) {
    debug('adding token:', req.session.token);
    req.headers.authorization = `Bearer ${req.session.token}`
  } else if(options.tokenOverride && process.env.NODE_ENV === 'development') {
    debug('overriding with token:', options.tokenOverride);
    req.headers.authorization = `Bearer ${options.tokenOverride}`;
  } else {
    debug('no token to add');
  }
  proxy.web(req, res);
};

function setupSessionManager(app, options) {
  if(options.redisConfig) {
    app.use(`/${options.apiPrefix}`, session({
      store: new RedisStore(options.redisConfig),
      secret: options.sessionSecret
    }));
    debug('Using Redis store at ', `${options.redisConfig.host}:${options.redisConfig.port}`);
  } else if(options.sessionConfig) {
    options.sessionConfig.secret = options.sessionSecret;
    app.use(`/${options.apiPrefix}`, session(options.sessionConfig));
    debug('Using memory store. Sessions will not persist after restart.')
  } else {
    throw new Error('Either a sessionConfig or a redisConfig must be specified.');
  }
}

export default function (app, overrides) {

  configure(overrides);
  setupSessionManager(app, options);

  app.use(`/${options.apiPrefix}/login`, bodyParser.json());
  app.post(`/${options.apiPrefix}/login`, login);
  app.post(`/${options.apiPrefix}/logout`, logout);
  app.use(`/${options.apiPrefix}`, apiProxy);
}
