'use strict';

Object.defineProperty(exports, '__esModule', {
  value: true
});

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { 'default': obj }; }

var _bodyParser = require('body-parser');

var _bodyParser2 = _interopRequireDefault(_bodyParser);

var _httpProxy = require('http-proxy');

var _httpProxy2 = _interopRequireDefault(_httpProxy);

var _request = require('request');

var _request2 = _interopRequireDefault(_request);

var _expressSession = require('express-session');

var _expressSession2 = _interopRequireDefault(_expressSession);

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

var proxy = undefined;

function debug() {
  if (options.debug) {
    for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    console.log(args);
  }
}

function setupProxy(options) {
  proxy = _httpProxy2['default'].createProxyServer({
    target: options.apiHost + ':' + options.apiPort,
    changeOrigin: true // otherwise heroku claims app doesn't exist: http://stackoverflow.com/a/6445766/583755
  });

  // https://github.com/nodejitsu/node-http-proxy/issues/839
  proxy.on('proxyReq', function (proxyReq, req, res) {
    var apiRequestPath = '/' + options.apiPrefix + proxyReq.path;
    debug('api request, going to path: ', apiRequestPath);
    proxyReq.path = apiRequestPath;
  });

  // added the error handling to avoid https://github.com/nodejitsu/node-http-proxy/issues/527
  proxy.on('error', function (error, req, res) {
    var json = undefined;
    debug('proxy error', error);
    if (!res.headersSent) {
      res.writeHead(500, { 'content-type': 'application/json' });
    }

    json = { error: 'proxy_error', reason: error.message };
    res.end(JSON.stringify(json));
  });
}

function configure(overrides) {
  for (var key in overrides) {
    options[key] = overrides[key];
  }
  debug('JWT Config options:', options);

  options.sessionConfig = {
    secret: options.sessionSecret,
    resave: false,
    saveUninitialized: false
  };

  setupProxy(options);
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
    response = JSON.parse(response.body);
    if (!error && response.access_token) {
      var token = response.access_token;
      debug('auth returned access token', token);
      req.session.token = token;
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
  });
}

function logout(req, res) {
  req.session.destroy(function (err) {
    debug('error destroying session', err);
  });
  res.sendStatus(200);
}

function apiProxy(req, res) {
  if (req.session.token) {
    debug('adding token:', req.session.token);
    req.headers.authorization = 'Bearer ' + req.session.token;
  } else if (options.tokenOverride && process.env.NODE_ENV === 'development') {
    debug('overriding with token:', options.tokenOverride);
    req.headers.authorization = 'Bearer ' + options.tokenOverride;
  } else {
    debug('no token to add');
  }
  proxy.web(req, res);
};

exports['default'] = function (app, overrides) {

  configure(overrides);

  app.use('/' + options.apiPrefix, (0, _expressSession2['default'])(options.sessionConfig));
  app.use('/' + options.apiPrefix + '/login', _bodyParser2['default'].json());
  app.post('/' + options.apiPrefix + '/login', login);
  app.post('/' + options.apiPrefix + '/logout', logout);
  app.use('/' + options.apiPrefix, apiProxy);
};

module.exports = exports['default'];