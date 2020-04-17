'use strict';
/**
 * Use the empty favicon middleware.
 */
const etag = require('etag'),
  fs = require('fs'),
  path = require('path');
module.exports = (app) => {
  const maxAge = 60 * 60 * 24 * 31 * 1000; // 1 MONTH
  let icon;
  /* read the favicon */
  try {
    let buff = fs.readFileSync(path.normalize(__dirname + '/favicon.ico'));
    icon = createIcon(buff, maxAge);
  } catch (e) {
    return;
  }

  return function favicon(req, res, next) {
    if (!req._parsedUrl) return next();
    if (req._parsedUrl.pathname !== '/favicon.ico') return next();

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.statusCode = req.method === 'OPTIONS' ? 200 : 405;
      res.setHeader('Allow', 'GET, HEAD, OPTIONS');
      res.setHeader('Content-Length', '0');
      res.end();
      return;
    }
    send(req, res, icon);
  };
};

function createIcon(buf, maxAge) {
  return {
    body: buf,
    headers: {
      'Cache-Control': 'public, max-age=' + Math.floor(maxAge / 1000),
      'ETag': etag(buf)
    }
  };
}

function send(req, res, icon) {
  let headers = icon.headers;

  // Set headers
  let keys = Object.keys(headers);
  for (let i = 0; i < keys.length; i++) {
    let key = keys[i];
    res.setHeader(key, headers[key]);
  }

  res.statusCode = 200;
  res.setHeader('Content-Length', icon.body.length);
  res.setHeader('Content-Type', 'image/x-icon');
  res.end(icon.body);
}
