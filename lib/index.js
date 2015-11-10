'use strict';

Object.defineProperty(exports, '__esModule', {
  value: true
});

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }

var _bodyParser = require('body-parser');

var _bodyParser2 = _interopRequireDefault(_bodyParser);

var _request = require('request');

var _request2 = _interopRequireDefault(_request);

var _expressSession = require('express-session');

var _expressSession2 = _interopRequireDefault(_expressSession);

var RedisStore = require('connect-redis')(_expressSession2['default']);

var options = {
  jwtClientId: undefined,
  jwtClientSecret: undefined,
  tokenOverride: undefined,
  authenticationEndpoint: undefined,
  apiHost: undefined,
  apiPort: 80,
  apiPrefix: 'api',
  debug: false
};

function debug() {
  if (options.debug) {
    for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    console.log(args);
  }
}

function configure(overrides) {
  for (var key in overrides) {
    options[key] = overrides[key];
  }
  debug('JWT Config options:', options);
}

function refreshAuth(req, res) {
  return new Promise(function (resolve, reject) {
    debug('refreshing token');
    var form = {
      grant_type: 'refresh_token',
      refresh_token: req.session.refresh_token
    };
    (0, _request2['default'])({
      method: 'POST',
      url: options.authenticationEndpoint,
      form: form
    }, function (error, response, body) {
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
  req.session.save(function (err) {
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
  var form = {
    grant_type: 'password',
    email: req.body.user.email,
    password: req.body.user.password
  };
  // client id and secret are not always required, only add if specified
  if (options.jwtClientId && options.jwtClientSecret) {
    form.jwtClientId = options.jwtClientId;
    form.jwtClientSecret = options.jwtClientSecret;
  }
  (0, _request2['default'])({
    method: 'POST',
    url: options.authenticationEndpoint,
    form: form
  }, function (error, response, body) {
    handleAuthResponse(error, response, body, req, res);
  });
}

function logout(req, res) {
  req.session.destroy(function (err) {
    debug('error destroying session', err);
  });
  res.sendStatus(200);
}

function apiProxy(req, res) {
  var headers = {};
  headers['Content-Type'] = 'application/json';

  if (req.session.access_token) {
    var now = new Date().getTime() / 1000;
    var secondsSinceCreation = Math.round(now - Number(req.session.created_at));
    var hasExpired = secondsSinceCreation > Number(req.session.expires_in);

    debug('seconds since creation', secondsSinceCreation);
    debug('greater than expiry?', hasExpired);

    if (hasExpired && req.session.refresh_token) {
      debug('access token expired');
      refreshAuth(req, res).then(function () {
        debug('refresh auth successful, now making proxied call');
        headers.authorization = 'Bearer ' + req.session.access_token;
        makeProxiedCall(req, res, headers);
      })['catch'](function () {
        debug('failed to refresh token');
        headers.authorization = 'Bearer ' + req.session.access_token;
        makeProxiedCall(req, res, headers);
      });
    } else {
      debug('adding token:', req.session.access_token);
      headers.authorization = 'Bearer ' + req.session.access_token;
      makeProxiedCall(req, res, headers);
    }
  } else if (options.tokenOverride && process.env.NODE_ENV === 'development') {
    debug('overriding with token:', options.tokenOverride);
    headers.authorization = 'Bearer ' + options.tokenOverride;
    makeProxiedCall(req, res, headers);
  } else {
    debug('no token to add');
    makeProxiedCall(req, res, headers);
  }
};

function makeProxiedCall(req, res, headers) {
  var requestOptions = {
    method: req.method,
    headers: headers
  };
  if (req.method === 'GET') {
    requestOptions.url = options.apiHost + ':' + options.apiPort + '/' + req.originalUrl;
  } else {
    requestOptions.url = options.apiHost + ':' + options.apiPort + '/' + options.apiPrefix + req.url;
    requestOptions.json = true;
    requestOptions.body = req.body;
  }
  debug('proxying to api', requestOptions);

  (0, _request2['default'])(requestOptions, function (error, serviceResponse, body) {
    if (serviceResponse.statusCode >= 200 && serviceResponse.statusCode < 300) {
      res.status(serviceResponse.statusCode);
      res.set(serviceResponse.headers);
      res.json(body);
    } else {
      debug('api not ok.', serviceResponse.statusCode, error, body);
      res.status(serviceResponse.statusCode);
      res.send(body);
    }
  });
}

function setupSessionManager(app, options) {
  if (options.redisConfig) {
    app.use((0, _expressSession2['default'])({
      store: new RedisStore(options.redisConfig),
      secret: options.sessionSecret
    }));
    var url = options.redisConfig.url || options.redisConfig.host + ':' + options.redisConfig.port;
    debug('Using Redis store at ', url);
  } else if (options.sessionConfig) {
    options.sessionConfig.secret = options.sessionSecret;
    app.use((0, _expressSession2['default'])(options.sessionConfig));
    debug('Using memory store. Sessions will not persist after restart.');
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

exports['default'] = function (app, overrides) {
  configure(overrides);
  setupSessionManager(app, options);

  app.use('/' + options.apiPrefix, _bodyParser2['default'].json());
  app.post('/' + options.apiPrefix + '/login', login);
  app.post('/' + options.apiPrefix + '/logout', logout);
  app.use(addSessionStateHeader);
  app.use('/' + options.apiPrefix, apiProxy);
};

module.exports = exports['default'];