# express-jwt-proxy

An express middleware to route login requests to an external authentication server and store JWT's and add them to headers en route to an external service.

## Install

`npm install express-jwt-proxy`

## Usage

```
const app = new Express();

jwtProxy(app, {
  authenticationEndpoint: `${process.env.AUTHENTICATION_HOST}/oauth/token`, // required
  jwtClientSecret: process.env.JWT_CLIENT_SECRET,
  jwtClientId: process.env.JWT_CLIENT_ID,
  sessionSecret: process.env.SESSION_SECRET, // required
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

## License

[MIT](LICENSE)
