import util from 'util';
import bodyParser from 'body-parser';
import request from 'request';
import session from 'express-session';

const RedisStore = require('connect-redis')(session);

let options;
const defaults = {
  api: {
    endpoint: '/api',
    host: undefined,
    port: 80,
    tokenOverride: undefined
  },
  auth: {
    clientId: undefined,
    clientSecret: undefined,
    endpoint: undefined
  },
  debug: false,
  endpoint: '/api',
  sessionStore: {
    type: 'memory',
    resave: false,
    saveUninitialized: false
  }
};

function debug(...args) {
  if (options.debug) {
    const utilOptions = {
      depth: 12,
      colors: true
    };

    console.log(util.inspect(args, utilOptions));
  }
}

function parse(obj) {
  try {
    return JSON.parse(obj);
  } catch (error) {
    return null;
  }
}

function configure(overrides) {
  options = Object.assign(defaults, overrides);
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
      url: options.auth.endpoint,
      form: form
    }, (error, response, body) => {
      if (error || !response || !parse(response.body) || !parse(response.body).access_token) {
        debug('failed to refresh token', error);
        reject(error);
      } else {
        storeToken(req, parse(response.body));
        resolve();
      }
    });
  });
}

function storeToken(req, tokenData) {
  return new Promise((resolve, reject) => {
    if (!tokenData) {
      reject('no token data received to store')
    }
    if (!req.session) {
      reject('no session retrieved from store. is redis down?');
    }

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
        reject(err);
      } else {
        resolve('token stored');
      }
    });
  })
}

function handleAuthResponse(error, response, body, req, res) {
  if (error || !response || !parse(response.body) || !parse(response.body).access_token) {
    debug('auth error', body);
    res.sendStatus(401);
  } else {
    storeToken(req, parse(response.body))
      .then(() => {
        res.status(200).json({ result: 'Success' });
      })
      .catch((err) => {
        debug(err);
        res.sendStatus(401);
      })    
  }
}

function login(req, res) {
  const form = {
    grant_type: 'password',
    email: req.body.user.email,
    password: req.body.user.password
  }
  // client id and secret are not always required, only add if specified
  if (options.auth.clientId && options.auth.clientSecret) {
    form.jwtClientId = options.auth.clientId;
    form.jwtClientSecret = options.auth.clientSecret;
  }
  request({
    method: 'POST',
    url: options.auth.endpoint,
    form: form
  }, (error, response, body) => {
    // console.log('got response from auth server:', error, response);
    handleAuthResponse(error, response, body, req, res);
  });
}

function logout(req, res) {
  if (req.session) {
    req.session.destroy((err) => {
      debug('error destroying session', err);
    });
  } else {
    debug('error destroying session. does not exist. is redis down?');
  }
  res.status(200).json({ result: 'Success' });
}

function apiProxy(req, res) {
  let headers = {};
  headers['Content-Type'] = 'application/json';

  if (req.session && req.session.access_token) {
    const now = new Date().getTime() / 1000;
    const secondsSinceCreation = Math.round(now - Number(req.session.created_at));
    const hasExpired = secondsSinceCreation > Number(req.session.expires_in);

    debug('seconds since creation', secondsSinceCreation);
    debug('greater than expiry?', hasExpired);

    if (hasExpired && req.session.refresh_token) {
      debug('access token expired');
      refreshAuth(req, res).then(() => {
        debug('refresh auth successful, now making proxied call');
        headers.authorization = `Bearer ${req.session.access_token}`
        makeProxiedCall(req, res, headers);
      }).catch(() => {
        debug('failed to refresh token');
        headers.authorization = `Bearer ${req.session.access_token}`
        makeProxiedCall(req, res, headers);
      })
    } else {
      debug('adding token:', req.session.access_token);
      headers.authorization = `Bearer ${req.session.access_token}`
      makeProxiedCall(req, res, headers);
    }
  } else if (options.api.tokenOverride && process.env.NODE_ENV === 'development') {
    debug('overriding with token:', options.api.tokenOverride);
    headers.authorization = `Bearer ${options.api.tokenOverride}`;
    makeProxiedCall(req, res, headers);
  } else {
    debug('no token to add or no session exists');
    makeProxiedCall(req, res, headers);
  }
};

function makeProxiedCall(req, res, headers) {
  let requestOptions = {
    method: req.method,
    headers: headers,
    url: options.api.host + ':' + options.api.port + options.api.endpoint + req.url
  }
  if (req.method !== 'GET') {
    requestOptions.json = true;
    requestOptions.body = req.body;
  }
  debug('proxying to api', requestOptions);

  request(requestOptions, (error, serviceResponse, body) => {
    if (!error && serviceResponse && serviceResponse.statusCode >= 200 && serviceResponse.statusCode < 400) {
      res.status(serviceResponse.statusCode);
      res.set(serviceResponse.headers);
      res.json(body);
    } else if (serviceResponse) {
      debug('api not ok.', serviceResponse.statusCode, error, body);
      res.status(serviceResponse.statusCode);
      res.json(body);
    } else {
      debug('api not ok. no response.', error, body);
      res.send(error);
    }
  });
}

function setupSessionManager(app, options) {
  if (options.sessionStore.type === 'redis') {
    const redisConfig = Object.assign(options.sessionStore, { store: new RedisStore(options.sessionStore) });
    // object assign is removing these if not specified in project config
    redisConfig.resave = false;
    redisConfig.saveUninitialized = false;
    debug('Using Redis for session store');
    app.use(session(redisConfig));
  } else {
    debug('Using memory session store.');
    app.use(session(options.sessionStore));
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

  app.use(`${options.endpoint}`, bodyParser.json());
  app.post(`${options.endpoint}/login`, login);
  app.post(`${options.endpoint}/logout`, logout);
  app.use(addSessionStateHeader);
  app.use(`${options.endpoint}`, apiProxy);
}
