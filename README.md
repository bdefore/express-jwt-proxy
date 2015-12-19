# express-jwt-proxy

An Express middleware to route login requests to an external authentication server and store JWT's and add them to headers en route to an external service.

## Install

`npm install express-jwt-proxy`

## Usage

```javascript
const isProduction = process.env.NODE_ENV === 'production';
const apiPortDefault = isProduction ? 443 : 3000;
const apiPort = process.env.API_PORT || apiPortDefault;

const authConfig = {
  api: {
    endpoint: '/v1',
    host: process.env.API_HOST || 'http://localhost',
    port: process.env.API_PORT || apiPortDefault
  },
  auth: {
    clientId: isProduction ? process.env.JWT_CLIENT_ID : undefined,
    clientSecret: isProduction ? process.env.JWT_CLIENT_SECRET : undefined,
    endpoint: `${process.env.AUTHENTICATION_HOST}/authenticate`
  },
  debug: !isProduction,
  endpoint: '/api',
  sessionStore: {
    type: 'redis',
    prefix: 'jwt-example',
    secret: process.env.JWT_CLIENT_SECRET,
    url: process.env.REDIS_URL
  }
}

const app = new Express();

jwtProxy(app, authConfig);
```

You should then be able to use the following routes:

`POST {config.apiPrefix}/login`: Accepts a user object with `email` and `password` properties. These will be sent in a POST request to `authenticationEndpoint` and the response will contain an `access_token` which will be stored for that user's session.

`POST {config.apiPrefix}/logout`: Will destroy the record of that user's JWT from the session

`{config.apiPrefix}/*`: Will redirect to the configured API endpoint, appending the JWT stored in the session to the header

In your subsequent middleware, you'll be able to access the login state by using the following:

```
const loggedIn = res._headers['logged-in'] === "true";
```

## Examples

- [Using Universal Redux npm package](https://github.com/bdefore/universal-redux/tree/0.x/examples/jwt)

## Inspiration

http://alexbilbie.com/2014/11/oauth-and-javascript/

## License

[MIT](LICENSE)
