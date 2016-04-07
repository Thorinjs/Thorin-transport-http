'use strict';
const express = require('express'),
  path = require('path'),
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

module.exports = function(thorin) {
  const config = Symbol(),
    defaultHandlerPath = Symbol(),
    defaultHandlerVerb = 'POST',
    paths = Symbol(),
    disabledActions = Symbol(),
    actions = Symbol(),
    server = Symbol();

  var logger; // this is the logger received from the transport.

  class ThorinExpressApp {

    constructor(appConfig, appLogger) {
      logger = appLogger;
      this.running = false;
      this[config] = appConfig;
      this[server] = null;
      let defaultHandler = path.normalize(this[config].basePath + '/' + this[config].actionPath);
      defaultHandler = defaultHandler.replace(/\\/g,'/');
      this[defaultHandlerPath] = defaultHandler;
      this[actions] = {}; // hash of {actionName:actionObj}
      this[disabledActions] = {};
      this[paths] = [];
    }

    /*
    * Handles an action through the default handler.
    * */
    addHandler(actionObj, verb, url) {
      if(typeof this[actions][actionObj.name] === 'undefined') {
        this[actions][actionObj.name] = actionObj;
      }
      if(typeof verb !== 'string') return true; // handled throught default handler
      verb = verb.toLowerCase();
      url = path.normalize(this[config].basePath + '/' + url);
      url = url.replace(/\\/g,'/');
      if(this.running) {
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
      // handle CORS
      registerCors(app, this[config].cors);
      // Handle static assets
      registerStaticPaths(app, this[config].static);
      // Handle middleware
      registerMiddleware(app, this[config]);
      this[server] = app;
      app.listen(this[config].port, this[config].ip, (e) => {
        if(e) return done(e);
        logger('info', 'Listening on port %s', this[config].port);
        this.running = true;
        if(typeof this[config].actionPath === 'string') {
          registerDefaultAction.call(this, defaultHandlerVerb, this[defaultHandlerPath]);
        }
        for(let i=0; i < this[paths].length; i++) {
          let item = this[paths][i];
          registerActionPath.call(this, item.verb, item.url, item.name);
        }
        this[paths] = null;
        app.use(handleRequestNotFound);
        app.use(handleRequestError);
        done();
      });
    }
  }

  /*
   * Performs the basic configurations for the express app.
   * */
  function configureApp(app, config) {
    app.set('query parser', 'simple');
    app.set('x-powered-by', false);
    if(thorin.env === 'production') {
      app.set('env', 'production');
    }
    app.set('views', undefined);
    app.set('view cache', false);
    if(config.trustProxy) {
      app.set('trust proxy', true);
    }
  }

  /*
  * Returns the authorization information from a request,
  * based on the configured values.
  *
  * */
  function getAuthorizationData(config, req) {
    let data = null;
    switch(config.source.toLowerCase()) {
      case 'header':
        try {
          data = req.header(config.name) || null;
        } catch(e) {}
        break;
      case 'cookie':
        try {
          data = req.cookies[config.name] || null;
        } catch(e) {}
        break;
    }
    return data;
  }

  /*
  * Includes any custom middleware functions.
  * TODO: user supplied middleware.
  * */
  function registerMiddleware(app, config) {
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
  }


  /* Handles the Not Found error */
  function handleRequestNotFound(req, res, next) {
    req.uniqueId = ++uniqueRequestId;
    req.startAt = Date.now();
    return next(thorin.error('TRANSPORT.NOT_FOUND', 'The requested resource was not found: ' + req.url, 404));
  }

  /* Handle any kind of error. */
  function handleRequestError(err, req, res, next) {
    let reqErr,
      reqData,
      statusCode = 400;
    if(err instanceof SyntaxError) {  // any other error, we bubble up.
      reqErr = thorin.error(PARSE_ERROR_CODE, 'Invalid payload.', err);
      statusCode = 400;
      reqData = reqErr.toJSON();
    } else if(err instanceof Error && err.name.indexOf('Thorin') === 0) {
      reqErr = err;
      statusCode = err.statusCode || 400;
      reqData = reqErr.toJSON();
    } else if(typeof err === 'object' && err.id) {
      reqErr = err.error;
      reqData = err;
      statusCode = reqErr.statusCode || 400;
    } else {
      switch(err.status) {
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
    } catch(e) {}
    // TODO: include the HTML 404 not found pages.
    let logMsg = '[END ' + req.uniqueId + "] " + statusCode + ' - ',
      logLevel = 'trace',
      logErr;
    if(req.action) logMsg += "(" + req.action + ") ";
    if(statusCode === 404) {
      logMsg += reqErr.message;
    } else if(statusCode < 500) {
      logMsg += reqErr.code + ' ' + reqErr.message;
    } else {
      logLevel = 'warn';
      logErr = reqErr;
    }
    let took = Date.now() - req.startAt;
    logMsg += " (" + took + "ms)";
    logger(logLevel, logMsg, logErr);
    try {
      res.json(reqData);
    } catch(e) {
      console.error('Thorin.transport.http: failed to finalize request with error: ', reqErr);
      console.error(e);
      try {
        res.end(reqErr.message);
      } catch(e) {
        return;
      }
    }
  }

  /*
  * Checks if we have CORS handling for the app.
  * */
  function registerCors(app, corsConfig) {
    if(corsConfig == false) return;
    let domains = [];
    if(typeof corsConfig === 'string') {
      domains = corsConfig.split(' ');
    }
    app.use((req, res, next) => {
      let origin = req.headers['origin'] || req.headers['referer'] || null,
        shouldAddHeaders = false;
      if(corsConfig === true) {
        shouldAddHeaders = true;
      } else if(domains.length > 0 && typeof origin === 'string') {
        let idx1 = origin.indexOf('://');
        if(idx1 !== -1) {
          origin = origin.substr(idx1 + 3);
        }
        let idx2 = origin.indexOf('/');
        if(idx2 !== -1) {
          origin = origin.substr(0, idx2);
        }
        for(let i=0; i < domains.length; i++) {
          // specific domains
          if(domains[i] === origin) {
            shouldAddHeaders = true;
            break;
          }
          // subdomains
          if(domains[i].charAt(0) === '.') {
            let matchSub = origin.substr(0- domains[i].length);
            if(matchSub === domains[i]) {
              shouldAddHeaders = true;
              break;
            }
          }
        }
      }
      if(!shouldAddHeaders) return next();
      res.header('Access-Control-Allow-Origin', req.headers['origin'] || '*');
      res.header('Access-Control-Allow-Methods', 'GET POST PUT DELETE OPTIONS');
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Allow-Headers', '*');
      next();
    });
  }


  function registerStaticPaths(app, paths) {
    if(!paths) return;  // no static.
    if(!(paths instanceof Array)) paths = [paths];
    paths.forEach((sPath) => {
      // we check if it's a root path
      if(sPath.charAt(0) === '/' || sPath.charAt(0) === '\\') {
        sPath = path.normalize(sPath);
      } else if(/[a-zA-Z]/.test(sPath.charAt(0)) && sPath.charAt(1) === ':') { // windows drivers.
        sPath = path.normalize(sPath);
      } else {  // thorin.root + sSath;
        sPath = path.normalize(thorin.root + '/' + sPath);
      }
      try {
        let stat = fs.lstatSync(sPath);
        if(!stat.isDirectory()) throw 1;
      } catch(e) {
        return;
      }
      let dirname = path.basename(sPath);
      const staticHandler = express.static(sPath, STATIC_OPTIONS);
      if(dirname === 'public' || paths.length === 1) {
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
      if(name == null || typeof name === 'undefined') return;
      target[name] = source[name];
    });
  }
  /*
   * This is the actual express handler for incoming requests.
   * */
  function handleIncomingRequest(actionType, req, res, next) {
    req.uniqueId = ++uniqueRequestId;
    req.startAt = Date.now();
    req.action = actionType;
    if(typeof this[actions][actionType] === 'undefined') {
      return handleRequestError(thorin.error('TRANSPORT.NOT_FOUND', 'The requested resource was not found: ' + req.url, 404), req, res, next);
    }
    // check if it was disabled.
    if(this[disabledActions][actionType] === true) {
      return handleRequestError(thorin.error('TRANSPORT.UNAVAILABLE', 'The requested URL is temporary unavailable: ' + req.url, 502), req, res, next);
    }
    let logMsg = '[START ' + req.uniqueId + '] - ' + actionType;
    logMsg += " (" + req.method.toUpperCase() + ' ' + req.originalUrl + ')';
    logger('trace', logMsg);
    // build the incoming data.
    const inputData = {};
    // insert query
    parseRequestInput(req.query, inputData);
    // insert body
    parseRequestInput(req.body, inputData);
    // insert param
    parseRequestInput(req.params, inputData);
    // attach the source ip address.
    const intentObj = new thorin.Intent(actionType, inputData,
      handleIntentSuccess.bind(this, req, res, next),
      handleIntentError.bind(this, req, res, next)
    );
    // set up authorization information.
    intentObj.authorization = getAuthorizationData(this[config].authorization, req);
    // set up client information (headers, ip)
    const clientData = {
      ip: req.ip,
      headers: req.headers
    };
    intentObj.client(clientData);
    thorin.dispatcher.triggerIntent(intentObj);
  }

  /*
  * Handles the actual success of the request's result.
  * */
  function handleIntentSuccess(req, res, next, data, intentObj) {
    let took = Date.now() - req.startAt,
      status = 200;
    try {
      res.status(status);
    } catch(e) {}
    try {
      try {
        data.result = data.result.toJSON();
      } catch(e) {}
      res.json(data);
    } catch(e) {
      console.error('Thorin.transport.http: failed to handleIntentSuccess', e);
    }
    let logMsg = '[END ' + req.uniqueId + '] ' + status + ' - ' + req.action;
    logMsg += ' (' + req.method.toUpperCase() + ' ' + req.originalUrl + ")";
    logMsg += ' (' + took + 'ms)';
    logger('trace', logMsg);

  }

  /*
  * Handles the actual error of the request's result.
  * TODO: manage the errors with a view error.
  * */
  function handleIntentError(req, res, next, data) {
    return handleRequestError(data, req, res, next);
  }

  /*
  * Binds the given handler to the path.
  * */
  function registerActionPath(verb, url, actionName) {
    var app = this[server];
    var reqHandler = handleIncomingRequest.bind(this, actionName);
    app[verb](url, reqHandler);
    // We have to insert the action handler right before the notfound handler.
    let requestLayer = app._router.stack.pop(); // last one added
    let wasInserted = false;
    for(let i=0; i < app._router.stack.length; i++) {
      if(app._router.stack[i].name === 'handleRequestNotFound') {
        app._router.stack.splice(i, 0, requestLayer);
        wasInserted = true;
        break;
      }
    }
    if(!wasInserted) {
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
  function registerDefaultAction(verb, url) {
    this[server][verb.toLowerCase()](url, (req, res, next) => {
      if(typeof req.body !== 'object' || !req.body || typeof req.body.action === 'undefined') {
        return next(thorin.error('TRANSPORT.INVALID_ACTION', 'Invalid or missing action', 404));
      }
      let actionType = req.body.action;
      let payload = req.body.payload || {};
      req.url = actionType;
      req.body = payload;
      req.query = {};
      req.params = {};
      handleIncomingRequest.call(this, actionType, req, res, next);
    });
  }

  return ThorinExpressApp;
};