'use strict';
const express = require('express'),
  path = require('path'),
  cookie = require('cookie'),
  helmet = require('helmet'),
  bodyParser = require('body-parser'),
  fs = require('fs');
/**
 * Created by Adrian on 02-Apr-16.
 */

/*
 * Binds any static paths to the app server.
 * */
const STATIC_OPTIONS = {
  index: 'index.html',
  dotfiles: 'ignore',
  maxAge: 2 * 60 * 60000  // 2 hours
};
var uniqueRequestId = 0;
const PARSE_ERROR_CODE = 'TRANSPORT.INVALID_PAYLOAD';

module.exports = function (thorin) {
  const config = Symbol(),
    defaultHandlerPath = Symbol(),
    defaultHandlerVerb = 'POST',
    paths = Symbol(),
    middleware = Symbol(),
    rootMiddleware = Symbol(),
    disabledActions = Symbol(),
    actions = Symbol(),
    httpServer = Symbol(),
    server = Symbol();

  var logger; // this is the logger received from the transport.

  class ThorinExpressApp {

    constructor(appConfig, appLogger) {
      logger = appLogger;
      this.running = false;
      this[config] = appConfig;
      this[server] = null;
      let defaultHandler = path.normalize(this[config].basePath + '/' + this[config].actionPath);
      defaultHandler = defaultHandler.replace(/\\/g, '/');
      this[defaultHandlerPath] = defaultHandler;
      this[actions] = {}; // hash of {actionName:actionObj}
      this[disabledActions] = {};
      this[paths] = [];
      this[middleware] = [];
      this[rootMiddleware] = [];
    }

    /*
     * Default intent JSON parser that return type: 'action', result: {}
     * The callback will be called with (err, data)
     * */
    parseIntentJson(err, data, req, intentObj) {
      if (err) return err;
      return data;
    }

    handleIntentJson(fn) {
      this.parseIntentJson = fn;
      return this;
    }

    _addMiddleware(fn) {
      this[middleware].push(fn);
      return this;
    }

    _addRootMiddleware(fn) {
      if (this.running || typeof fn !== 'function') return false;
      this[rootMiddleware].push(fn);
      return true;
    }

    /*
     * Expose the getAuthorizationData functionality for a given request.
     * This should ONLY be used by other plugins.
     * */
    _getAuthorization(req, _config) {
      return getAuthorizationData(_config || this[config].authorization, req);
    }

    /*
     * Expose the handleIntentSuccess() functionality for a given request.
     * This should ONLY be used by other plugins.
     * */
    _sendIntentSuccess(intentObj, req, res) {
      let data = {
        result: intentObj.result()
      };
      try {
        data.result = data.result.toJSON();
      } catch (e) {
      }
      handleIntentSuccess(req, res, null, data, intentObj);
    }

    /*
     * Exposes the request's uniqueId funcitonality
     * This shoulD ONLY be used by other plugins.
     * */
    _requestUniqueId() {
      return uniqueRequestId++;
    }

    /*
     * Expose the HTTP Server. This should ONLY be used by other transports,
     * as it may distrupt the way it works.
     * */
    _getHttpServer() {
      return this[httpServer] || null;
    }

    /*
     * Handles an action through the default handler.
     * */
    addHandler(actionObj, verb, url) {
      if (typeof this[actions][actionObj.name] === 'undefined') {
        this[actions][actionObj.name] = actionObj;
      }
      if (typeof verb !== 'string') return true; // handled throught default handler
      verb = verb.toLowerCase();
      url = path.normalize(this[config].basePath + '/' + url);
      url = url.replace(/\\/g, '/');
      if (this.running) {
        registerActionPath.call(this, verb, url, actionObj.name);
        return this;
      }
      this[paths].push({
        verb: verb,
        url: url,
        name: actionObj.name
      });
      return this;
    }

    /*
     * Disables a handler
     * */
    disableHandler(name) {
      this[disabledActions][name] = true;
    }

    enableHandler(name) {
      delete this[disabledActions][name];
    }

    /*
     * Binds the HTTP Server and starts listening for requests.
     * */
    listen(done) {
      const app = express();
      configureApp(app, this[config]);
      // Configure Helmet
      configureHelmet(app, this[config].helmet);
      // handle CORS
      registerCors(app, this[config].cors);
      // Handle static assets
      registerStaticPaths(app, this[config].static);
      // Handle middleware
      registerMiddleware.call(this, app, this[config]);
      this[server] = app;
      let isDone = false;
      this[httpServer] = app.listen(this[config].port, this[config].ip, (e) => {
        if (e) return done(e);
        if (isDone) return;
        logger('info', 'Listening on port %s', this[config].port);
        this.running = true;
        if (typeof this[config].actionPath === 'string') {
          registerDefaultAction.call(this, defaultHandlerVerb, this[defaultHandlerPath]);
        }
        for (let i = 0; i < this[paths].length; i++) {
          let item = this[paths][i];
          registerActionPath.call(this, item.verb, item.url, item.name);
        }
        this[paths] = null;
        app.use(handleRequestNotFound.bind(this));
        app.use(handleRequestError.bind(this));
        isDone = true;
        done();
      });
      this[httpServer].on('error', (e) => {
        if (!isDone) {
          isDone = true;
          if (e.code === 'EADDRINUSE') {
            return done(thorin.error('TRANSPORT.PORT_IN_USE', `The port ${this[config].port} or ip ${this[config].ip} is already in use.`));
          }
          return done(thorin.error(e));
        }
        logger.warn('Thorin HTTP Transport encountered an error:', e);
      });
    }
  }

  /*
   * Performs the basic configurations for the express app.
   * */
  function configureApp(app, config) {
    app.set('query parser', 'simple');
    app.set('x-powered-by', false);
    if (thorin.env === 'production') {
      app.set('env', 'production');
    }
    app.set('views', undefined);
    app.set('view cache', false);
    if (config.trustProxy) {
      app.set('trust proxy', true);
    }
  }

  /*
   * Configures the app to work with helmet
   * */
  function configureHelmet(app, config) {
    if (typeof config !== 'object' || !config) return; // helmet disabled.
    app.use(helmet(config));
  }

  /*
   * Returns the authorization information from a request,
   * based on the configured values.
   *
   * */
  function getAuthorizationData(config, req) {
    let data = null,
      types = Object.keys(config);
    for (let i = 0; i < types.length; i++) {
      let authType = types[i],
        authName = config[authType];
      if (authType === 'header') {
        try {
          let tmp = req.headers[authName] || req.headers[authName.toLowerCase()] || null;
          if (typeof tmp !== 'string' || !tmp) throw 1;
          if (tmp.indexOf('Bearer ') === 0) {
            tmp = tmp.substr(7);
          }
          tmp = tmp.trim();
          if (tmp === '') throw 1;
          data = tmp;
          break;
        } catch (e) {
        }
      }
      if (authType === 'cookie') {
        try {
          let tmp = cookie.parse(req.headers['cookie']);
          if (typeof tmp[authName] !== 'string') throw 1;
          tmp = tmp[authName].trim();
          if (tmp === '') throw 1;
          data = tmp;
          break;
        } catch (e) {
        }
      }
    }
    return data;
  }

  /*
   * Includes any custom middleware functions.
   * */
  function registerMiddleware(app, config) {
    /* Parse root middlewares. */
    for (let i = 0; i < this[rootMiddleware].length; i++) {
      app.use(this[rootMiddleware][i]);
    }
    delete this[rootMiddleware];
    /* Parse Form data */
    app.use(bodyParser.urlencoded({
      extended: false,
      limit: config.options.payloadLimit,
      parameterLimit: 500
    }));
    /* Parse JSON in the body */
    app.use(bodyParser.json({
      limit: config.options.payloadLimit
    }));
    /* attach any middleware */
    for (let i = 0; i < this[middleware].length; i++) {
      app.use(this[middleware][i]);
    }
    this[middleware] = [];
  }


  /* Handles the Not Found error */
  function handleRequestNotFound(req, res, next) {
    if (typeof req.uniqueId === 'undefined') {
      req.uniqueId = ++uniqueRequestId;
    }
    req.startAt = Date.now();
    let msg = 'The requested resource was not found';
    if(this[config].actionPath !== req.url) {
      msg += `: ${req.method} ${req.url}`;
    } else if(req._actionType) {
      msg += ': ' + req._actionType;
    }
    return next(thorin.error('TRANSPORT.NOT_FOUND', msg, 404));
  }

  /* Handle any kind of error. */
  function handleRequestError(err, req, res, next) {
    // In order to make errors visible, we have to set CORS for em.
    let intentObj;
    if(req.intent) {
      intentObj = req.intent;
      delete req.intent;
    }

    try {
      res.header('Access-Control-Allow-Origin', req.headers['origin'] || '*');
      res.header('Access-Control-Allow-Methods', req.method.toUpperCase() + ', OPTIONS');
      res.header('Access-Control-Allow-Credentials', 'true');
    } catch (e) {
    }
    let reqErr,
      reqData,
      statusCode = 400;
    if (err instanceof SyntaxError) {  // any other error, we bubble up.
      reqErr = thorin.error(PARSE_ERROR_CODE, 'Invalid payload.', err);
      statusCode = 400;
      reqData = {
        error: reqErr.toJSON()
      };
    } else if (err instanceof Error && err.name.indexOf('Thorin') === 0) {
      reqErr = err;
      statusCode = err.statusCode || 400;
      reqData = {
        error: reqErr.toJSON()
      };
    } else if (typeof err === 'object' && err.type) {
      if (err.type === 'entity.too.large') {
        reqErr = thorin.error(PARSE_ERROR_CODE, 'Payload too large', err.statusCode);
      } else {
        reqErr = thorin.error(err.error);
      }
      reqData = {
        error: reqErr.toJSON()
      };
      statusCode = reqErr && reqErr.statusCode || 400;
    } else {
      switch (err.status) {
        case 415: // encoding unsupported.
          reqErr = thorin.error(PARSE_ERROR_CODE, 'Encoding unsupported', err);
          break;
        case 400: // aborted
          reqErr = thorin.error(PARSE_ERROR_CODE, 'Request aborted', err);
          break;
        case 413: // payload large
          reqErr = thorin.error(PARSE_ERROR_CODE, 'Payload too large', err);
          break;
        default:
          reqErr = thorin.error(err);
          statusCode = 500;
      }
      reqData = {
        error: reqErr.toJSON()
      };
    }
    try {
      res.status(statusCode);
    } catch (e) {
    }
    let logErr;
    // TODO: include the HTML 404 not found pages.
    if (req._hasDebug !== false) {
      let logMsg = '[ENDED',
        logLevel = 'trace';
      if (req.uniqueId) {
        logMsg += ' ' + req.uniqueId;
      }
      logMsg += '] -';
      if (req.action) logMsg += ' ' + req.action;
      logMsg += " (" + req.method.toUpperCase() + ' ' + req.originalUrl.substr(0, 64) + ') ';
      logMsg += '= ' + statusCode + ' ';
      if (statusCode === 404) {
        if (reqErr.code !== 'TRANSPORT.NOT_FOUND') {
          logMsg += '[' + reqErr.code + '] ';
        }
        logMsg += reqErr.message;
      } else if (statusCode < 500) {
        logMsg += '[' + reqErr.code + '] ' + reqErr.message;
      } else {
        logMsg += '[' + reqErr.code + ']';
        logLevel = 'warn';
        logErr = reqErr;
      }
      if (req.startAt) {
        let took = Date.now() - req.startAt;
        logMsg += " (" + took + "ms)";
      }
      logger(logLevel, logMsg, logErr);
    }
    try {
      if (this[config].debug && logErr.source) {
        logger('warn', logErr.source.stack);
      }
    } catch (e) {
    }
    // Check if we have a buffer in our rawData
    if (err.rawData instanceof Buffer) {
      try {
        res.set({
          'Content-Type': 'application/octet-stream'
        });
      } catch (e) {
      }
      try {
        res.send(err.rawData);
      } catch (e) {
        console.error('Thorin.transport.http: failed to send error buffer to response.');
        console.debug(e);
        try {
          res.end();
        } catch (e) {
        }
      }
    } else if (typeof err.rawData === 'string') {
      try {
        res.type('html');
      } catch (e) {
      }
      try {
        res.send(err.rawData);
      } catch (e) {
        console.error('Thorin.transport.http: failed to send error string to response.');
        console.debug(e);
        try {
          res.end();
        } catch (e) {
        }
      }
    } else {
      try {
        if (req.exposeType === false && reqData.type) {
          delete reqData.type;
        }
        try {
          reqData = this.parseIntentJson(reqData, null, req, intentObj);
        } catch (e) {
        }
        res.json(reqData);
      } catch (e) {
        console.error('Thorin.transport.http: failed to finalize request with error: ', reqErr);
        console.error(e);
        try {
          res.end(reqErr.message);
        } catch (e) {
        }
      }
    }
  }

  /*
   * Checks if we have CORS handling for the app.
   * */
  function registerCors(app, corsConfig) {
    if (corsConfig == false) return;
    let domains = [];
    if (typeof corsConfig === 'string') {
      domains = corsConfig.split(' ');
    } else if (corsConfig instanceof Array) {
      domains = corsConfig;
    }
    app.use((req, res, next) => {
      let origin = req.headers['origin'] || req.headers['referer'] || null,
        shouldAddHeaders = false,
        rawOrigin = origin;
      if (corsConfig === true) {
        shouldAddHeaders = true;
      } else if (domains.length > 0 && typeof origin === 'string') {
        let idx1 = origin.indexOf('://');
        if (idx1 !== -1) {
          origin = origin.substr(idx1 + 3);
        }
        let idx2 = origin.indexOf('/');
        if (idx2 !== -1) {
          origin = origin.substr(0, idx2);
        }
        for (let i = 0; i < domains.length; i++) {
          // specific domains
          if (domains[i] === origin) {
            shouldAddHeaders = true;
            break;
          }
          // subdomains
          if (domains[i].charAt(0) === '.') {
            let matchSub = origin.substr(0 - domains[i].length);
            if (matchSub === domains[i]) {
              shouldAddHeaders = true;
              break;
            }
          }
          // match proto
          if (domains[i].indexOf('://') !== -1 && rawOrigin.indexOf(domains[i]) === 0) {
            shouldAddHeaders = true;
            break;
          }
        }
      }
      if (!shouldAddHeaders) return next();
      res.header('Access-Control-Allow-Origin', rawOrigin || '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Allow-Headers', '*');
      next();
    });
  }


  function registerStaticPaths(app, paths) {
    if (!paths) return;  // no static.
    if (!(paths instanceof Array)) paths = [paths];
    paths.forEach((sPath) => {
      // we check if it's a root path
      if (sPath.charAt(0) === '/' || sPath.charAt(0) === '\\') {
        sPath = path.normalize(sPath);
      } else if (/[a-zA-Z]/.test(sPath.charAt(0)) && sPath.charAt(1) === ':') { // windows drivers.
        sPath = path.normalize(sPath);
      } else {  // thorin.root + sSath;
        sPath = path.normalize(thorin.root + '/' + sPath);
      }
      try {
        let stat = fs.lstatSync(sPath);
        if (!stat.isDirectory()) throw 1;
      } catch (e) {
        return;
      }
      let dirname = path.basename(sPath);
      const staticHandler = express.static(sPath, STATIC_OPTIONS);
      if (dirname === 'public' || paths.length === 1) {
        app.use(staticHandler);
      } else {
        app.use('/' + dirname, staticHandler);
      }
    });
  }

  /*
   * This will parse the incoming data to the intent input.
   * */
  function parseRequestInput(source, target) {
    Object.keys(source).forEach((name) => {
      if (name == null || typeof name === 'undefined') return;
      target[name] = source[name];
    });
  }

  /*
   * This is the actual express handler for incoming requests.
   * */
  function handleIncomingRequest(actionType, alias, req, res, next) {
    if (typeof req.uniqueId === 'undefined') {
      req.uniqueId = ++uniqueRequestId;
      req.startAt = Date.now();
    }
    req.action = actionType;
    if (typeof this[actions][actionType] === 'undefined') {
      let msg = 'The requested resource was not found';
      if(this[config].actionPath !== req.url) {
        msg += `: ${req.method} ${req.url}`;
      }
      return handleRequestError.call(this, thorin.error('TRANSPORT.NOT_FOUND', msg, 404), req, res, next);
    }
    req._hasDebug = this[actions][actionType].hasDebug;
    req.exposeType = (this[actions][actionType].defaultHandle === true);
    // check if it was disabled.
    if (this[disabledActions][actionType] === true) {
      return handleRequestError.call(this, thorin.error('TRANSPORT.UNAVAILABLE', 'The requested URL is temporary unavailable: ' + req.url, 502), req, res, next);
    }
    if (thorin.env !== 'production' && req._hasDebug) {
      let logMsg = '[START ' + req.uniqueId + '] - ' + actionType;
      logMsg += " (" + req.method.toUpperCase() + ' ' + req.originalUrl.substr(0, 64) + ')';
      logger('trace', logMsg);
    }
    // build the incoming data.
    const inputData = {};
    // insert query
    parseRequestInput(req.query, inputData);
    // insert body
    parseRequestInput(req.body, inputData);
    // insert param
    parseRequestInput(req.params, inputData);

    // The HTTP Transport will attach the .redirect(url) option in the intent.
    // NOTE: redirects will ignore attached results or errors.

    // attach the source ip address.
    let redirectTo = null, redirectCode = 302, isFinished = false;
    const actionObj = this[actions][actionType];
    const intentObj = new thorin.Intent(actionType, inputData, (wasError, data, intentObj) => {
      isFinished = true;
      if (actionObj && actionObj.cors) {
        let corsDomain = actionObj.cors.domain || '*',
          methods = ['OPTIONS'];
        if (req.method !== 'OPTIONS') {
          methods.push(req.method);
        }
        res.header('Access-Control-Allow-Origin', corsDomain);
        res.header('Access-Control-Allow-Methods', methods.join(', '));
        res.header('Access-Control-Allow-Credentials', actionObj.cors.credentials);
        res.header('Access-Control-Allow-Headers', '*');
      }
      let resultHeaders = intentObj.resultHeaders();
      if (resultHeaders && !res.headersSent) {
        Object.keys(resultHeaders).forEach((name) => {
          let value = resultHeaders[name];
          if (typeof value !== 'string') return;
          try {
            res.append(name, value);
          } catch (e) {
          }
        });
      }
      if (redirectTo != null) {
        // redirect the request.
        handleIntentRedirect.call(this, req, res, intentObj, redirectTo, redirectCode);
        return;
      }
      let sendFn = (wasError ? handleIntentError : handleIntentSuccess);
      sendFn.call(this, req, res, next, data, intentObj);
    });
    // IF we are coming from an alias, attach it.
    if (alias) {
      intentObj.alias = alias;
      intentObj.url = req.url;
    }
    /* Attach the redirect functionality */
    intentObj.redirect = function PerformRedirect(url, _code) {
      if (typeof url !== 'string') return this;
      redirectTo = url;
      if (typeof _code === 'number') {
        redirectCode = _code;
      }
      intentObj._canRender = false;
      // IF code is set to false, we do not directly send()
      if (_code === false) {
        return this;
      }
      return this.send();
    };
    // set up authorization information.
    let authToken = getAuthorizationData(this[config].authorization, req);
    if (authToken) {
      intentObj._setAuthorization('TOKEN', authToken);
    }
    intentObj.transport = 'http';
    // set up client information (headers, ip)
    const clientData = {
      ip: req.ip,
      headers: req.headers
    };
    intentObj.client(clientData);
    function onRequestClose() {
      req.removeListener('close', onRequestClose);
      if(isFinished) return;
      try {
        intentObj.__trigger(thorin.Intent.EVENT.CLOSE);
      } catch (e) {
      }
    }

    req.on('close', onRequestClose);
    thorin.dispatcher.triggerIntent(intentObj);
  }

  /* Handles an intent redirect. */
  function handleIntentRedirect(req, res, intentObj, redirectUrl, redirectCode) {
    try {
      res.redirect(redirectCode, redirectUrl);
    } catch (e) {
      logger('warn', "Failed to perform redirect on action " + req.action, e);
    }
    if (req._hasDebug !== false) {
      let logMsg = '[ENDED ' + req.uniqueId + "] - ",
        took = Date.now() - req.startAt;
      logMsg += req.action + ' ';
      logMsg += "(" + req.method.toUpperCase() + ' ' + req.originalUrl.substr(0, 64) + ') ';
      logMsg += '= ' + redirectCode + ' => ' + redirectUrl + ' ';
      logMsg += '(' + took + 'ms)';
      logger('trace', logMsg);
    }
  }

  /*
   * Handles the actual success of the request's result.
   * */
  function handleIntentSuccess(req, res, next, data, intentObj) {
    let took = Date.now() - req.startAt,
      status = 200;
    try {
      res.status(status);
    } catch (e) {
    }
    // We're sending a string or HTML
    let contentType = res.get('content-type');
    if (typeof data === 'string') {
      if (!contentType) {
        let isHtml = data.indexOf("DOCTYPE ") !== -1 || data.indexOf("<html") !== -1 || data.indexOf("</") !== -1 || data.indexOf("/>") !== -1;
        if (isHtml) {
          res.type('html');
        } else {
          res.type('text');
        }
      }
      res.end(data);
    } else if (data instanceof Buffer) {
      // we have a buffer, possibly a download occurring
      try {
        if (!contentType) {
          res.set({
            'Content-Type': 'application/octet-stream'
          });
        }
        res.send(data);
      } catch (e) {
        console.error('Thorin.transport.http: failed to send buffer to response.');
        console.debug(e);
      }
    } else if (typeof data === 'object' && data != null) {
      try {
        try {
          data.result = data.result.toJSON();
        } catch (e) {
        }
        if (req.exposeType === false && data.type) {
          delete data.type;
        }
        try {
          data = this.parseIntentJson(null, data, req, intentObj);
        } catch (e) {
        }
        res.json(data);
      } catch (e) {
        console.error('Thorin.transport.http: failed to handleIntentSuccess', e);
        try {
          res.end();
        } catch (e) {
        }
      }
    } else {
      res.end(data);
    }
    if (req._hasDebug !== false) {
      let logMsg = '[ENDED ' + req.uniqueId + "] - ";
      logMsg += req.action + ' ';
      logMsg += "(" + req.method.toUpperCase() + ' ' + req.originalUrl.substr(0, 64) + ') ';
      logMsg += '= ' + status + ' ';
      logMsg += '(' + took + 'ms)';
      logger('trace', logMsg);
    }

  }

  /*
   * Handles the actual error of the request's result.
   * TODO: manage the errors with a view error.
   * */
  function handleIntentError(req, res, next, data, intentObj) {
    if (intentObj.hasRawResult()) {
      data.rawData = intentObj.result();
    }
    req.intent = intentObj;
    return handleRequestError.call(this, data, req, res, next);
  }

  /*
   * Binds the given handler to the path.
   * */
  function registerActionPath(verb, url, actionName) {
    var app = this[server];
    var reqHandler = handleIncomingRequest.bind(this, actionName, url);
    app[verb](url, reqHandler);
    // We have to insert the action handler right before the notfound handler.
    let requestLayer = app._router.stack.pop(); // last one added
    let wasInserted = false;
    for (let i = 0; i < app._router.stack.length; i++) {
      if (app._router.stack[i].name === 'bound handleRequestNotFound') {
        app._router.stack.splice(i, 0, requestLayer);
        wasInserted = true;
        break;
      }
    }
    if (!wasInserted) {
      app._router.stack.push(requestLayer);
    }
  }

  /*
   * Binds to the default frux handler.
   * The default frux handler will handle incoming POST request with:
   *   body.action -> the action we want to process.
   *   body.payload -> the payload we want to attach to it.
   *   If action is not specified, we fail.
   * */
  function setCors(req, res, verb) {
    res.header('Access-Control-Allow-Origin', req.headers['origin'] || '*');
    res.header('Access-Control-Allow-Methods', verb.toUpperCase() + ', OPTIONS');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || '*');
  }

  function registerDefaultAction(verb, url) {
    /* Handle the OPTIONS method of /dispatch */
    this[server].options(url, (req, res, next) => {
      setCors(req, res, verb);
      res.end();
    });
    /* Handle the POST method of /dispatch */
    this[server][verb.toLowerCase()](url, (req, res, next) => {
      setCors(req, res, verb);
      req.uniqueId = ++uniqueRequestId;
      req.startAt = Date.now();
      if (typeof req.body !== 'object' || !req.body || typeof req.body.type === 'undefined' || req.body.type === '') {
        return next(thorin.error('TRANSPORT.INVALID_TYPE', 'Invalid or missing action type', 404));
      }
      let actionType = req.body.type;
      if (!this[actions][actionType] || !this[actions][actionType].defaultHandle) {
        req._actionType = actionType;
        return handleRequestNotFound.call(this, req, res, next);
      }
      let payload = req.body.payload || {};
      req.url = actionType;
      req.body = payload;
      req.query = {};
      req.params = {};
      handleIncomingRequest.call(this, actionType, null, req, res, next);
    });
  }

  return ThorinExpressApp;
};