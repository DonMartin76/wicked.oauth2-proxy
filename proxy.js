'use strict';

const http = require('http');
const httpProxy = require('http-proxy');
const express = require('express');
const cookie = require('cookie');
const crypto = require('crypto');
const redisLib = require('redis');
const redis = redisLib.createClient({ host: '127.0.0.1' });

const REDIS_EXPIRE_SECS = 30;

const app = express();

//
// Create a proxy server with custom application logic
//
const proxy = httpProxy.createProxyServer({});

function createRandomId() {
  return crypto.randomBytes(20).toString('hex');
}

function cookieMe(req, res) {
  console.log('No valid Cookie received, request to: ' + req.path);
  if (req.path === '/cookieme') {
    const sessionId = createRandomId();
    console.log('Creating new session ' + sessionId);
    redis.set(sessionId, 'old mcdonald had a farm', function (err) {
      if (err)
        return res.send('Oh, this is not good.');
      redis.expire(sessionId, REDIS_EXPIRE_SECS);
      res.setHeader('Set-Cookie', cookie.serialize('proxySession', sessionId));
      return res.send('<a href="/">You are logged in</a>.');
    });
    return;
  }
  res.send('No no no. <a href="/cookieme">Cookie!</a>');
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
  console.log('Status code: ' + res.statusCode);
});

proxy.on('proxyReq', function (proxyReq, req, res, options) {
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
  redis.get(sessionId + '.cookie', function (err, result) {
    if (err)
      return res.send('Booo, bad redis.');
    req.upstreamCookie = result;
    redis.expire(sessionId + '.cookie', REDIS_EXPIRE_SECS);

    proxy.web(req, res, { target: 'http://localhost:3000' });
  });
});

//
// Create your custom server and just call `proxy.web()` to proxy
// a web request to the target passed in the options
// also you can use `proxy.ws()` to proxy a websockets request
//
const server = http.createServer(app);

console.log("listening on port 5050");
server.listen(5050);
