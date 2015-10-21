# express-jwt-proxy

An Express middleware to route login requests to an external authentication server and store JWT's and add them to headers en route to an external service.

## Install

`npm install express-jwt-proxy`

## Usage

```
const app = new Express();

jwtProxy(app, {
  authenticationEndpoint: `${process.env.AUTHENTICATION_HOST}/oauth/token`, // required
  jwtClientSecret: process.env.JWT_CLIENT_SECRET,
  jwtClientId: process.env.JWT_CLIENT_ID,
  tokenOverride: process.env.JWT_TOKEN_OVERRIDE,
  sessionSecret: process.env.SESSION_SECRET, // required
  // store in memory, when not using redis
  // sessionConfig: {
  //   resave: false,
  //   saveUninitialized: false
  // },
  // store using redis
  redisConfig: {
    prefix: 'my-app-name',
    host: '127.0.0.1',
    port: 6379
  },
  apiPrefix: config.apiPrefix, // required
  apiHost: config.apiHost, // required
  apiPort: config.apiPort, // required
  debug: false
});
```

You should then be able to use the following routes:

`POST {config.apiPrefix}/login`: Accepts a user object with `email` and `password` properties. These will be sent in a POST request to `authenticationEndpoint` and the response will contain an `access_token` which will be stored for that user's session.

`POST {config.apiPrefix}/logout`: Will destroy the record of that user's JWT from the session

`{config.apiPrefix}/*`: Will redirect to the configured API endpoint, appending the JWT stored in the session to the header

In your subsequent middleware, you'll be able to access the login state by using the following:

```
const loggedIn = res._headers['logged-in'] === "true";
```

## TODO / Help Wanted

- Examples

## Inspiration

http://alexbilbie.com/2014/11/oauth-and-javascript/

## License

[MIT](LICENSE)
