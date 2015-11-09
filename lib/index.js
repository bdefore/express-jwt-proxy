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
    handleAuthResponse(error, response, body, req, res);
  });
}

function handleAuthResponse(error, response, body, req, res) {
  response = JSON.parse(response.body);
  if (!error && response.access_token) {
    req.session.access_token = response.access_token;
    req.session.refresh_token = response.refresh_token;
    debug('auth returned access token', req.session.access_token);
    debug('auth returned refresh token', req.session.refresh_token);
    req.session.save(function (err) {
      if (err) {
        debug('error saving session', err);
      }
    });
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
  if (req.session.access_token) {
    debug('adding token:', req.session.access_token);
    headers.authorization = 'Bearer ' + req.session.access_token;
  } else if (options.tokenOverride && process.env.NODE_ENV === 'development') {
    debug('overriding with token:', options.tokenOverride);
    headers.authorization = 'Bearer ' + options.tokenOverride;
  } else {
    debug('no token to add');
  }
  headers['Content-Type'] = 'application/json';

  var url = options.apiHost + ':' + options.apiPort + '/' + options.apiPrefix + req.url;
  console.log('proxying to api at url:', url);
  (0, _request2['default'])({
    method: req.method,
    url: url,
    headers: headers
  }, function (error, serviceResponse, body) {
    if (serviceResponse.statusCode === 401) {
      res.sendStatus(401);
    } else {
      res.set(serviceResponse.headers);
      res.json(body);
    }
  });
};

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

  app.use('/' + options.apiPrefix + '/login', _bodyParser2['default'].json());
  app.post('/' + options.apiPrefix + '/login', login);
  app.post('/' + options.apiPrefix + '/logout', logout);
  app.use(addSessionStateHeader);
  app.use('/' + options.apiPrefix, apiProxy);
};

module.exports = exports['default'];