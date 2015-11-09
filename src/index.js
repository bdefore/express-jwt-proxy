import bodyParser from 'body-parser';
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

function debug(...args) {
  if (options.debug) {
    console.log(args);
  }
}

function configure(overrides) {
  for(const key in overrides) {
    options[key] = overrides[key]
  }
  debug('JWT Config options:', options);
}

function refreshAuth(req, res) {
  return new Promise((resolve, reject) => {
    debug('refreshing token');
    const form = {
      grant_type: 'refresh_token',
      refresh_token: req.session.refresh_token
    }
    request({
      method: 'POST',
      url: options.authenticationEndpoint,
      form: form
    }, (error, response, body) => {
      debug('refreshAuth error?', error);
      response = JSON.parse(response.body);
      if (!error && response.access_token) {
        storeToken(req, response);
        resolve();
      } else {
        debug('failed to refresh token', error);
        reject(error);
      }
    });
  });
}

function storeToken(req, tokenData) {
  req.session.access_token = tokenData.access_token;
  req.session.refresh_token = tokenData.refresh_token;
  req.session.expires_in = tokenData.expires_in;
  req.session.created_at = tokenData.created_at;
  debug('auth returned access token', req.session.access_token);
  debug('auth returned refresh token', req.session.refresh_token);
  debug('auth returned expires in', req.session.expires_in);
  debug('auth returned created at', req.session.created_at);
  req.session.save((err) => {
    if (err) {
      debug('error saving session', err);
    }
  });
}

function handleAuthResponse(error, response, body, req, res) {
  response = JSON.parse(response.body);
  if (!error && response.access_token) {
    storeToken(req, response);
    res.sendStatus(200);
  } else {
    debug('auth error', body);
    res.sendStatus(401);
  }
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
    handleAuthResponse(error, response, body, req, res);
  });
}

function logout(req, res) {
  req.session.destroy((err) => {
    debug('error destroying session', err);
  });
  res.sendStatus(200);
}

function apiProxy(req, res) {
  let headers = {};
  headers['Content-Type'] = 'application/json';

  if (req.session.access_token) {
    const now = new Date().getTime() / 1000;
    const timeSinceCreation = Math.round(now - Number(req.session.created_at));
    const hasExpired = timeSinceCreation > Number(req.session.expires_in);

    debug('now', now);
    debug('created_at', req.session.created_at);
    debug('time since creation', timeSinceCreation);
    debug('greater than expiry?', hasExpired);
    debug('adding token:', req.session.access_token);

    if (hasExpired) {
      debug('access token expired');
      refreshAuth(req, res).then(() => {
        debug('refresh auth successful, now making proxied call');
        headers.authorization = `Bearer ${req.session.access_token}`
        makeProxiedCall(req, res, headers);
      })
    } else {
      headers.authorization = `Bearer ${req.session.access_token}`
      makeProxiedCall(req, res, headers);
    }
  } else if (options.tokenOverride && process.env.NODE_ENV === 'development') {
    debug('overriding with token:', options.tokenOverride);
    headers.authorization = `Bearer ${options.tokenOverride}`;
    makeProxiedCall(req, res, headers);
  } else {
    debug('no token to add');
    makeProxiedCall(req, res, headers);
  }
};

function makeProxiedCall(req, res, headers) {
  const url = options.apiHost + ':' + options.apiPort + '/' + options.apiPrefix + req.url;
  debug('proxying to api at url:', url);
  request({
    method: req.method,
    url: url,
    headers: headers
  }, (error, serviceResponse, body) => {
    if (serviceResponse.statusCode === 401) {
      res.sendStatus(401);
    } else {
      res.set(serviceResponse.headers);
      res.json(body);
    }
  });
}

function setupSessionManager(app, options) {
  if (options.redisConfig) {
    app.use(session({
      store: new RedisStore(options.redisConfig),
      secret: options.sessionSecret
    }));
    const url = options.redisConfig.url || `${options.redisConfig.host}:${options.redisConfig.port}`;
    debug('Using Redis store at ', url);
  } else if (options.sessionConfig) {
    options.sessionConfig.secret = options.sessionSecret;
    app.use(session(options.sessionConfig));
    debug('Using memory store. Sessions will not persist after restart.')
  } else {
    throw new Error('Either a sessionConfig or a redisConfig must be specified.');
  }
}

function addSessionStateHeader(req, res, next) {
  if (req.session && req.session.access_token) {
    res.set('logged-in', true);
  } else {
    res.set('logged-in', false);
  }
  next();
}

export default function (app, overrides) {
  configure(overrides);
  setupSessionManager(app, options);

  app.use(`/${options.apiPrefix}/login`, bodyParser.json());
  app.post(`/${options.apiPrefix}/login`, login);
  app.post(`/${options.apiPrefix}/logout`, logout);
  app.use(addSessionStateHeader);
  app.use(`/${options.apiPrefix}`, apiProxy);
}
