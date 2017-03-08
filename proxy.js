'use strict';

const http = require('http');
const httpProxy = require('http-proxy');
const express = require('express');
const cookie = require('cookie');
const crypto = require('crypto');
const request = require('request');
const redisLib = require('redis');
const redis = redisLib.createClient({ host: '127.0.0.1' });

const REDIS_EXPIRE_SECS = 120;

let invalidConfig = false;
if (!process.env.AUTH_SERVER_URL) {
  console.error('ERROR: Env var AUTH_SERVER_URL is not defined.');
  invalidConfig = true;
}
if (!process.env.API_GATEWAY_URL) {
  console.error('ERROR: Env var AUTH_SERVER_URL is not defined.');
  invalidConfig = true;
}
if (!process.env.CLIENT_ID) {
  console.error('ERROR: Env var CLIENT_ID is not defined.');
  invalidConfig = true;
}
if (!process.env.CLIENT_SECRET) {
  console.error('ERROR: Env var CLIENT_SECRET is not defined.');
  invalidConfig = true;
}
if (!process.env.REDIRECT_URI) {
  console.error('ERROR: Env var REDIRECT_URL is not defined.');
  invalidConfig = true;
}
if (invalidConfig) {
  console.error('Exiting due to misconfiguration.');
  process.exit(1);
}

const AUTH_SERVER_URL = process.env.AUTH_SERVER_URL;
const API_GATEWAY_URL = process.env.API_GATEWAY_URL;
let TOKEN_URL = urlCombine(API_GATEWAY_URL, '/oauth2/token');
if (process.env.TOKEN_URL)
  TOKEN_URL = process.env.TOKEN_URL;
else
  console.log('Using token URL ' + TOKEN_URL);
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const ALLOW_INSECURE = process.env.ALLOW_INSECURE ? true : false;

const https = require('https');
const agentOptions = { rejectUnauthorized: false };
const sslAgent = new https.Agent(agentOptions);

const app = express();

//
// Create a proxy server with custom application logic
//
const proxy = httpProxy.createProxyServer({});

function urlCombine(p1, p2) {
  const pp1 = p1.endsWith('/') ? p1.substring(0, p1.length - 1) : p1;
  const pp2 = p2.startsWith('/') ? p2.substring(1) : p2;
  return pp1 + '/' + pp2;
}

function createRandomId() {
  return crypto.randomBytes(20).toString('hex');
}

function errorPage(req, res, message) {
  res.send('Error: ' + message);
}

function cookieMe(req, res) {
  console.log('No valid Cookie received, request to: ' + req.path + ", " + req.url);
  if (req.path === '/callback') {
    // Verify we're right here and retrieve token
    if (!req.query)
      return errorPage(req, res, 'No query parameters given for /callback');
    const authorizationCode = req.query.code;
    if (!authorizationCode)
      return errorPage(req, res, 'Did not receive authorization code');
    const state = req.query.state;
    const requestOptions = {
      url: TOKEN_URL,
      body: {
        grant_type: 'authorization_code',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code: authorizationCode,
        redirect_uri: REDIRECT_URI
      },
      json: true
    };
    if (ALLOW_INSECURE)
      requestOptions.agent = sslAgent;
    request.post(requestOptions, function (err, apiResponse, apiBody) {
      if (err) {
        console.error('Did not receive an access token from token URL');
        console.error(err);
        return errorPage(req, res, 'Did not receive an access token from token URL');
      }
      if (apiResponse.statusCode !== 200) {
        console.error('Token end point did not return OK (200) return code: ' + apiResponse.statusCode);
        console.error(apiBody);
        return errorPage(req, res, 'Unexpected status code: ' + apiResponse.statusCode);
      }
      const accessToken = apiBody.access_token;
      const refreshToken = apiBody.refresh_token;

      console.log('State: ' + state);
      const sessionId = createRandomId();
      console.log('Creating new session ' + sessionId);
      redis.set(sessionId, accessToken, function (err) {
        if (err) {
          console.error(err);
          return errorPage(req, res, 'Could not persist session access token.');
        }
        redis.expire(sessionId, REDIS_EXPIRE_SECS);
        res.setHeader('Set-Cookie', cookie.serialize('proxySession', sessionId));
        return res.redirect(state);
      });
      //return errorPage(req, res, 'Actually, that went well');
    });
    // return;
  } else {
    res.redirect(AUTH_SERVER_URL + '?response_type=code' +
      '&client_id=' + CLIENT_ID +
      '&redirect_uri=' + encodeURIComponent(REDIRECT_URI) +
      '&state=' + encodeURIComponent(req.url));
  }
  //res.send('No no no. <a href="/cookieme">Cookie!</a>');
}

app.use(function (req, res, next) {
  if (req.headers.cookie) {
    console.log('--> From User Agent Cookie: ' + req.headers.cookie);
    const cookieObject = cookie.parse(req.headers.cookie);

    if (!cookieObject.proxySession)
      return cookieMe(req, res);
    const sessionId = cookieObject.proxySession;
    if (!/^[a-zA-Z0-9]+$/.test(sessionId)) {
      console.error('Received invalid session ID');
      return cookieMe(req, res);
    }
    redis.get(sessionId, function (err, value) {
      if (err || !value) {
        console.error('Could not retrieve session data from redis');
        return cookieMe(req, res);
      }
      redis.expire(sessionId, REDIS_EXPIRE_SECS);
      console.log('Retrieved session from redis: ' + value);
      req.sessionId = sessionId;
      return next();
    });
  } else {
    return cookieMe(req, res);
  }
});

function getCookieObject(setCookieHeader) {
  console.log(setCookieHeader);
  const cookieThing = cookie.parse(setCookieHeader);
  const cookieObject = {};
  for (let key in cookieThing) {
    switch (key.toLowerCase()) {
      case 'expires':
      case 'max-age':
      case 'secure':
      case 'httponly':
      case 'domain':
      case 'path':
        console.log('Skipping key ' + key);
        break;
      default:
        cookieObject[key] = cookieThing[key];
    }
  }
  return cookieObject;
}

function getCookieHeader(cookieObject) {
  let first = true;
  const parts = [];
  for (let key in cookieObject) {
    if (!first) {
      parts.push('; ');
    }
    first = false;
    parts.push(key + '=' + encodeURIComponent(cookieObject[key]));
  }
  return parts.join('');
}

proxy.on('proxyRes', function (proxyRes, req, res) {
  //console.log('RAW Response from the target', JSON.stringify(proxyRes.headers, true, 2));
  let setCookie = proxyRes.headers['set-cookie'];
  if (setCookie) {
    // Do not let this propagate upstream!
    delete proxyRes.headers['set-cookie'];
    // Store in redis
    if (Array.isArray(setCookie) && setCookie.length > 0) {
      setCookie = setCookie[0];
      console.log("From Target Set-Cookie: " + setCookie);
      const localCookie = getCookieHeader(getCookieObject(setCookie));
      console.log('Parsed Set-Cookie: ' + localCookie);

      redis.set(req.sessionId + '.cookie', localCookie, function (err) {
        if (err) {
          console.error('could not set cookie in redis');
        }
        redis.expire(req.sessionId + '.cookie', REDIS_EXPIRE_SECS);
      });
    } else {
      console.log('==== Unexpected type of Set-Cookie header');
    }
  }
  console.log('Status code: ' + proxyRes.statusCode);
});

proxy.on('proxyReq', function (proxyReq, req, res, options) {
  if (req.accessToken) {
    proxyReq.setHeader('Authorization', 'Bearer ' + req.accessToken);
  }
  if (req.upstreamCookie) {
    const cookieValue = req.upstreamCookie;
    console.log('Setting upstream Cookie: ' + cookieValue);
    proxyReq.setHeader('Cookie', cookieValue);
  } else if (proxyReq.getHeader('cookie')) {
    console.log('Removing cookie header.');
    proxyReq.removeHeader('cookie');
  }
});

app.use(function (req, res) {
  console.log(req.headers.host + ", " + req.url);

  const sessionId = req.sessionId; // this has to exist
  redis.get(sessionId, function (err, result) {
    if (err)
      return cookieMe(req, res);
    req.accessToken = result;
    redis.get(sessionId + '.cookie', function (err, result) {
      if (err)
        return cookieMe(req, res);
      req.upstreamCookie = result;
      redis.expire(sessionId + '.cookie', REDIS_EXPIRE_SECS);

      proxy.web(req, res, { target: API_GATEWAY_URL, secure: false, changeOrigin: true });
    });
  });
});

const server = http.createServer(app);

console.log("listening on port 5050");
server.listen(5050);
