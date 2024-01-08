'use strict';
const express = require('express'),
  path = require('path'),
  cookie = require('cookie'),
  helmet = require('helmet'),
  bodyParser = require('body-parser'),
  fs = require('fs');

const initFavicon = require('./favicon.js'),
  basicAuth = require('./basicAuth'),
  RouteLayer = require('express/lib/router/layer');

/**
 * Created by Adrian on 02-Apr-16.
 */
const MAX_REQUEST_ID = 10000;
/*
 * Binds any static paths to the app server.
 * */
const STATIC_OPTIONS = {
  index: 'index.html',
  dotfiles: 'ignore',
  maxAge: 2 * 60 * 60000  // 2 hours
};
const CORS_METHODS = 'GET, POST, PUT, DELETE, OPTIONS';

let uniqueRequestId = 0;

module.exports = function (thorin, logger) {

  const ERROR_NOT_FOUND = thorin.error('TRANSPORT.NOT_FOUND', 'The requested resource was not found', 404);
  const ERROR_UNAVAILABLE = thorin.error('TRANSPORT.UNAVAILABLE', 'The requested resource is temporary unavailable', 502);
  const ERROR_PARSE = thorin.error('TRANSPORT.INVALID_PAYLOAD', 'The request payload is not valid', 400);
  const ERROR_TOO_LARGE = thorin.error('TRANSPORT.INVALID_PAYLOAD', 'The request payload is too large', 413);
  const ERROR_ENCODING = thorin.error('TRANSPORT.INVALID_PAYLOAD', 'The requested encoding is not available', 415);
  const ERROR_ABORTED = thorin.error('TRANSPORT.ABORTED', 'The request was aborted', 400);
  const ERROR_DATA = thorin.error('TRANSPORT.DATA', 'Invalid or missing request information', 400, { field: 'type' });

  class ThorinExpress {

    #config = {};
    #defaultHandlerPath = [];
    #defaultHandlerVerb = 'POST';
    #globalHandler;
    #paths = [];
    #middleware = [];
    #rootMiddleware = [];
    #disabledActions = {};
    #actions = {};
    #actionPatterns = [];
    #httpServer = null;
    #server = null;

    constructor(config) {
      this.running = false;
      this.#config = config;
      this.#globalHandler = express();
      this.#configureApp(this.#globalHandler, this.#config);
      if (config.actionPath instanceof Array) {
        for (let i = 0; i < config.actionPath.length; i++) {
          let p = config.actionPath[i];
          let defaultHandler = path.normalize(config.basePath + '/' + p);
          defaultHandler = defaultHandler.replace(/\\/g, '/');
          this.#defaultHandlerPath.push(defaultHandler);
        }
      } else if (typeof config.actionPath === 'string') {
        let defaultHandler = path.normalize(config.basePath + '/' + config.actionPath);
        defaultHandler = defaultHandler.replace(/\\/g, '/');
        this.#defaultHandlerPath.push(defaultHandler);
      }
    }

    /**
     * Default intent JSON parser that return type: 'action', result: {}
     * The callback will be called with (err, data)
     * */
    parseIntentJson(err, data, req, intentObj) {
      if (err) return err;
      try {
        if (this.#config.hideType === true && data.type) {
          delete data.type;
        }
      } catch (e) {
      }
      return data;
    }

    /**
     * Override the default intent json
     * */
    handleIntentJson(fn) {
      this.parseIntentJson = fn;
      return this;
    }

    /**
     * Registers new middleware to use
     * */
    _addMiddleware(fn) {
      this.#middleware.push(fn);
      return this;
    }

    /**
     * Registers new express-level middlewares
     * */
    _addRootMiddleware(fn) {
      if (this.running || typeof fn !== 'function') return false;
      this.#rootMiddleware.push(fn);
      return true;
    }

    /**
     * Expose the getAuthorizationData functionality for a given request.
     * This should ONLY be used by other plugins.
     * */
    _getAuthorization(req, _config) {
      return this.#getAuthorizationData(_config || this.#config.authorization, req);
    }

    /**
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
      this.#handleIntentSuccess(req, res, null, data, intentObj);
    }

    /**
     * Exposes the request's uniqueId funcitonality
     * This shoulD ONLY be used by other plugins.
     * */
    _requestUniqueId() {
      if (uniqueRequestId >= MAX_REQUEST_ID) {
        uniqueRequestId = 0;
      }
      return uniqueRequestId++;
    }

    /**
     * Expose the HTTP Server. This should ONLY be used by other transports,
     * as it may distrupt the way it works.
     * */
    _getHttpServer() {
      return this.#httpServer || null;
    }


    /**
     * Handles an action through the default handler.
     * */
    addHandler(actionObj, verb, url) {
      if (typeof this.#actions[actionObj.name] === 'undefined') {
        this.#actions[actionObj.name] = actionObj;
      }
      // check if it is a match.
      let match = actionObj.__getMatch();
      if (match.length > 0) {
        for (let i = 0; i < match.length; i++) {
          this.#actionPatterns.push({
            match: match[i],
            action: actionObj.name
          });
        }
      }
      if (typeof verb !== 'string') return true; // handled throught default handler
      verb = verb.toLowerCase();
      url = path.normalize(this.#config.basePath + '/' + url).replace(/\\/g, '/');
      if (this.running) {
        this.#registerActionPath(verb, url, actionObj.name);
        return this;
      }
      let item = {
        verb: verb,
        url: url,
        name: actionObj.name
      };
      this.#paths.push(item);
      return this;
    }

    /**
     * Disables a handler
     * */
    disableHandler(name) {
      this.#disabledActions[name] = true;
    }

    /**
     * Enable a handler
     * */
    enableHandler(name) {
      delete this.#disabledActions[name];
    }

    /**
     * Binds the HTTP Server and starts listening for requests.
     * */
    listen(done) {
      const app = express();
      this.#server = app;
      this.#configureApp(app, this.#config);
      // Configure Helmet
      this.#configureHelmet(app, this.#config.helmet);
      // handle CORS
      this.#registerCors(app, this.#config.cors, this.#config.corsIgnore);
      // Handle static assets
      this.#registerStaticPaths(app, this.#config.static);
      // Handle middleware
      this.#registerMiddleware(app, this.#config);
      if (this.#defaultHandlerPath.length > 0) {
        this.#registerDefaultAction(this.#defaultHandlerVerb, this.#defaultHandlerPath);
      }
      app.use(this.#globalHandler);
      for (let i = 0; i < this.#paths.length; i++) {
        let item = this.#paths[i];
        this.#registerActionPath(item.verb, item.url, item.name);
      }
      this.#paths = null;
      app.use(this.#handleRequestNotFound);
      app.use(this.#handleRequestError);
      let isDone = false;
      this.#httpServer = app.listen(this.#config.port, this.#config.ip, (e) => {
        if (e) return done(e);
        if (isDone) return;
        logger.info(`Listening on port ${this.#config.port}`);
        this.running = true;
        isDone = true;
        done();
      });
      this.#httpServer.on('error', (e) => {
        if (!isDone) {
          isDone = true;
          if (e.code === 'EADDRINUSE') {
            return done(thorin.error('TRANSPORT.PORT_IN_USE', `The port ${this.#config.port} or ip ${this.#config.ip} is already in use.`));
          }
          return done(thorin.error(e));
        }
        logger.warn('Thorin HTTP Transport encountered an error:', e);
      });
    }


    /**
     * Performs the basic configurations for the express app.
     * */
    #configureApp = (app, config) => {
      app.set('query parser', 'simple');
      app.set('x-powered-by', false);
      app.disable('x-powered-by');
      if (app.env === 'production') {
        app.set('env', 'production');
      }
      app.set('views', undefined);
      app.set('view cache', false);
      if (config.trustProxy) {
        app.set('trust proxy', true);
      }
    }

    /**
     * Configures the app to work with helmet
     * */
    #configureHelmet = (app, config) => {
      if (typeof config !== 'object' || !config) return; // helmet disabled.
      app.use(helmet(config));
    }


    /**
     *  Check favicon middleware
     *  */
    #registerFavicon = (app, config) => {
      if (typeof config.static !== 'string' || !config.static) return;
      let stat;
      // check .ico
      try {
        stat = fs.lstatSync(config.static + '/favicon.ico');
        if (stat.isFile()) return;
      } catch (e) {
        if (e.code !== 'ENOENT') return;
      }
      let faviconFn = initFavicon(app, config);
      if (!faviconFn) return;
      app.use(faviconFn);
    }

    /**
     * Returns the authorization information from a request,
     * based on the configured values.
     *
     * */
    #getAuthorizationData = (config, req) => {
      let data = null,
        types = Object.keys(config);
      for (let i = 0; i < types.length; i++) {
        let authType = types[i],
          authName = config[authType];
        if (authType === 'header') {
          try {
            let tmp = req.headers[authName] || req.headers[authName.toLowerCase()] || null;
            if (typeof tmp !== 'string' || !tmp) throw 1;
            let bearer = tmp.substr(0, 7);
            if (bearer === 'Bearer ' || bearer === 'bearer ') {
              tmp = tmp.substr(7);
            }
            tmp = tmp.trim();
            if (tmp === '') throw 1;
            data = tmp;
            break;
          } catch (e) {
          }
        } else if (authType === 'cookie') {
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

    /**
     * Includes any custom middleware functions.
     * */
    #registerMiddleware = (app, config) => {
      /* Check for basic auth */
      if (config.authorization && typeof config.authorization.basic === 'object' && config.authorization.basic) {
        this.#registerBasicAuth(app, config.authorization.basic);
      }
      // Check if we have favicon
      this.#registerFavicon(app, config);
      /* Parse root middlewares. */
      for (let i = 0; i < this.#rootMiddleware.length; i++) {
        app.use(this.#rootMiddleware[i]);
      }
      this.#rootMiddleware = undefined;
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
      /* Parse raw text */
      if (config.rawText) {
        app.use(bodyParser.text({
          type: 'text/*',
          limit: config.options.payloadLimit
        }));
      }
      /* attach any middleware */
      for (let i = 0; i < this.#middleware.length; i++) {
        app.use(this.#middleware[i]);
      }
      this.#middleware = [];
    }

    /**
     * Registers basic authorization
     * */
    #registerBasicAuth = (app, authConfig) => {
      if (typeof authConfig.user !== 'string' || typeof authConfig.password !== 'string') return;
      app.use(function (req, res, next) {
        try {
          let credentials = basicAuth(req);
          if (!credentials || credentials.name !== authConfig.user || credentials.pass !== authConfig.password) {
            res.setHeader('WWW-Authenticate', `Basic realm="${config.realm || 'app'}"`);
            return next(thorin.error('UNAUTHORIZED', 'Authorization failed', 401));
          }
        } catch (e) {
          return next(e);
        }
        next();
      });
    }

    /**
     * Checks if we have CORS handling for the app.
     * */
    #registerCors = (app, corsConfig, corsIgnore) => {
      if (corsConfig === false) return;
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
        if (typeof rawOrigin === 'string') {
          let qsIdx = rawOrigin.indexOf('?');
          if (qsIdx !== -1) {
            rawOrigin = rawOrigin.substr(0, qsIdx);
          }
        }
        if (corsConfig === true) {
          shouldAddHeaders = true;
        } else if (domains.length > 0 && typeof origin === 'string') {
          origin = this.#getRawOrigin(origin);
          for (let i = 0; i < domains.length; i++) {
            let domain = domains[i],
              isMatch = this.#matchCorsOrigin(domain, origin, rawOrigin);
            if (isMatch) {
              shouldAddHeaders = true;
              break;
            }
          }
        }
        if (!shouldAddHeaders) return next();
        // CHECK if we have corsIgnore in settings
        let ignoreHosts;
        if (typeof corsIgnore === 'string') {
          ignoreHosts = [corsIgnore];
        } else if (corsIgnore instanceof Array) {
          ignoreHosts = corsIgnore;
        }
        if (ignoreHosts instanceof Array) {
          origin = this.#getRawOrigin(origin);
          for (let i = 0; i < ignoreHosts.length; i++) {
            let domain = ignoreHosts[i],
              isMatch = this.#matchCorsOrigin(domain, origin, rawOrigin);
            if (isMatch) return next();
          }
        }
        res.header('Access-Control-Allow-Origin', rawOrigin || '*');
        res.header('Access-Control-Allow-Methods', req.headers['access-control-request-methods'] || CORS_METHODS);
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || '*');
        res.header('Access-Control-Max-Age', (this.#config.corsAge).toString());
        next();
      });
    }

    /**
     * Check if we have any public/ path.
     * */
    #registerStaticPaths = (app, paths) => {
      if (!paths) return;  // no static.
      if (!(paths instanceof Array)) paths = [paths];
      paths.forEach((sPath) => {
        // we check if it's a root path
        if (sPath.charAt(0) === '/' || sPath.charAt(0) === '\\') {
          sPath = path.normalize(sPath);
        } else if (/[a-zA-Z]/.test(sPath.charAt(0)) && sPath.charAt(1) === ':') { // windows drivers.
          sPath = path.normalize(sPath);
        } else {  // app.root + sSath;
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

    /**
     * Binds the given handler to the path.
     * */
    #registerActionPath = (verb, url, actionName) => {
      let handler = this.#globalHandler;
      let self = this;
      handler[verb](url, function (req, res, next) {
        try {
          self.#handleIncomingRequest(actionName, url, req, res, next);
        } catch (e) {
          next(e);
        }
      });
    }

    /**
     * Binds to the default frux handler.
     * The default frux handler will handle incoming POST request with:
     *   body.action -> the action we want to process.
     *   body.payload -> the payload we want to attach to it.
     *   If action is not specified, we fail.
     * */
    #setCors = (req, res) => {
      let dom = this.#config.cors;
      if (dom === true) {
        dom = req.headers['origin'] || '*';
      } else if (dom instanceof Array) {
        if (!req.headers['origin']) {
          dom = false;
        } else {
          let found = false;
          for (let i = 0, len = dom.length; i < len; i++) {
            if (dom[i].indexOf(req.headers['origin']) === -1) continue;
            found = true;
            dom = dom[i];
            break;
          }
          if (!found) return;
        }
      }
      // CHECK if we have corsIgnore in settings
      let ignoreHosts;
      if (typeof this.#config.corsIgnore === 'string') {
        ignoreHosts = [this.#config.corsIgnore];
      } else if (this.#config.corsIgnore instanceof Array) {
        ignoreHosts = this.#config.corsIgnore;
      }
      if (ignoreHosts instanceof Array) {
        let origin = this.#getRawOrigin(dom);
        for (let i = 0; i < ignoreHosts.length; i++) {
          let domain = ignoreHosts[i],
            isMatch = this.#matchCorsOrigin(domain, origin, dom);
          if (isMatch) return;
        }
      }
      if (!dom) return;
      res.header('Access-Control-Allow-Origin', dom);
      res.header('Access-Control-Allow-Methods', req.headers['access-control-request-methods'] || CORS_METHODS);
      res.header('Access-Control-Allow-Credentials', 'true');
      res.header('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || '*');
      res.header('Access-Control-Max-Age', (this.#config.corsAge || 600).toString());
    }

    /**
     * Registers the default action and its OPTIONS request
     * */
    #registerDefaultAction = (verb, url) => {
      if (this.#config.cors) {
        this.#server.options('*', this.#handleOptions);
      }
      /* Handle the OPTIONS method of /dispatch */
      if (url instanceof Array) {
        for (let i = 0; i < url.length; i++) {
          this.#server.options(url[i], this.#handleOptions);
          this.#server[verb.toLowerCase()](url[i], this.#handleRequest);
        }
      } else if (typeof url === 'string' && url) {
        this.#server.options(url, this.#handleOptions);
        this.#server[verb.toLowerCase()](url, this.#handleRequest);
      }
    }


    /**
     * Returns the raw origin hostname.
     * */
    #getRawOrigin = (origin) => {
      let idx1 = origin.indexOf('://');
      if (idx1 !== -1) {
        origin = origin.substr(idx1 + 3);
      }
      let idx2 = origin.indexOf('/');
      if (idx2 !== -1) {
        origin = origin.substr(0, idx2);
      }
      return origin;
    }

    /**
     * Tries to match CORS origins.
     * */
    #matchCorsOrigin = (domain, origin, rawOrigin) => {
      if (domain === origin) return true;
      // subdomain
      if (domain.charAt(0) === '.') {
        let matchSub = origin.substr(0 - domain.length);
        if (matchSub === domain) return true;
      }
      // Match proto
      if (domain.indexOf('://') !== -1 && rawOrigin.indexOf(domain) === 0) {
        return true;
      }
      return false;
    }

    /**
     * This will parse the incoming data to the intent input.
     * */
    #parseRequestInput = (source, target) => {
      let keys = Object.keys(source);
      if (keys.length === 1) {
        // Check if we have our main key as the full JSON
        let tmp = keys[0],
          shouldParse = false;
        tmp = tmp.trim();
        if (tmp.charAt(0) === '{') {
          for (let i = 0; i < Math.min(tmp.length, 100); i++) {
            if (tmp[i] === '"') {
              shouldParse = true;
              break;
            }
          }
          if (shouldParse) {
            try {
              source = JSON.parse(tmp);
              keys = Object.keys(source);
            } catch (e) {
              return;
            }
          }
        }
      }
      keys.forEach((name) => {
        if (name == null || typeof name === 'undefined') return;
        target[name] = source[name];
      });
    }

    /**
     * Handles the POST method of /dispatch
     * */
    #handleRequest = (req, res, next) => {
      this.#setCors(req, res);
      req.uniqueId = ++uniqueRequestId;
      req.startAt = Date.now();
      if (typeof req.body !== 'object' || !req.body || typeof req.body.type !== 'string' || req.body.type === '') {
        return next(ERROR_DATA);
      }
      let actionType = req.body.type,
        wasFound = true;
      if (!this.#actions[actionType] || !this.#actions[actionType].defaultHandle) {
        wasFound = false;
      } else {
        req.action = actionType;
      }
      if (!wasFound) {
        for (let i = 0, len = this.#actionPatterns.length; i < len; i++) {
          let item = this.#actionPatterns[i];
          if (item.match.test(actionType)) {
            wasFound = true;
            req.action = actionType;
            actionType = item.action;
            break;
          }
        }
      }
      if (!wasFound) {
        req._actionType = actionType;
        return this.#handleRequestNotFound(req, res, next);
      }
      let payload = (typeof req.body.payload === 'object' && req.body.payload ? req.body.payload : {});
      if (typeof req.body.filter === 'object' && req.body.filter) {
        req.filter = req.body.filter;
      }
      if (typeof req.body.meta === 'object' && req.body.meta) {
        req.meta = req.body.meta;
      }
      req.url = req.action;
      req.body = payload;
      req.query = {};
      req.params = {};
      this.#handleIncomingRequest(actionType, null, req, res, next);
    }

    /**
     * Handles the 404 not found error.
     * */
    #handleRequestNotFound = (req, res, next) => {
      if (typeof req.uniqueId === 'undefined') {
        if (uniqueRequestId >= MAX_REQUEST_ID) {
          uniqueRequestId = 0;
        }
        req.uniqueId = ++uniqueRequestId;
      }
      req.startAt = Date.now();
      return next(ERROR_NOT_FOUND);
    }

    /**
     * Handles OPTIONS request
     * */
    #handleOptions = (req, res) => {
      let hasCors = !!this.#config.cors;
      if (hasCors) {
        this.#setCors(req, res);
      }
      res.end();
    }

    /**
     * This is the actual express handler for incoming requests.
     * */
    #handleIncomingRequest = (actionType, alias, req, res, next) => {
      if (typeof req.uniqueId === 'undefined') {
        req.uniqueId = ++uniqueRequestId;
        req.startAt = Date.now();
      }
      if (!req.action) {
        req.action = actionType;
      }
      if (typeof this.#actions[actionType] === 'undefined') {
        return this.#handleRequestError(ERROR_NOT_FOUND, req, res, next);
      }
      req._hasDebug = this.#actions[actionType].hasDebug;
      req.exposeType = (this.#actions[actionType].defaultHandle === true);
      // check if it was disabled.
      if (this.#disabledActions[actionType] === true) {
        return this.#handleRequestError(ERROR_UNAVAILABLE, req, res, next);
      }
      if (thorin.env !== 'production' && req._hasDebug) {
        let logMsg = '[START ' + req.uniqueId + '] - ' + req.action,
          rawUrl = this.#getShortUrl(req),
          rawQs = this.#getShortQuery(req);
        logMsg += " (" + req.method.toUpperCase() + ' ' + rawUrl + ')';
        logger.trace(logMsg, rawQs);
      }
      // build the incoming data.
      const inputData = {};
      // insert query
      if (typeof req.query === 'object' && req.query) {
        this.#parseRequestInput(req.query, inputData);
      }
      // insert body
      if (typeof req.body === 'object' && req.body) {
        this.#parseRequestInput(req.body, inputData);
      } else if (typeof req.body === 'string' && this.#config.rawText) {
        this.#parseRequestInput({
          _text: req.body
        }, inputData);
      }
      // insert param
      this.#parseRequestInput(req.params, inputData);

      // The HTTP Transport will attach the .redirect(url) option in the intent.
      // NOTE: redirects will ignore attached results or errors.
      // attach the source ip address.
      let isFinished = false;
      const actionObj = this.#actions[actionType];
      const intentObj = new thorin.Intent(actionType, inputData, (wasError, data, intentObj) => {
        isFinished = true;
        let hasCors = false,
          corsDomain,
          corsCredentials,
          corsMethods;
        if (intentObj.hasCors()) {
          hasCors = true;
          let corsData = intentObj.getCors();
          corsDomain = corsData.domain || '*';
          corsCredentials = corsData.credentials || false;
          if (corsData.methods) {
            corsMethods = corsData.methods;
          }
        } else if (actionObj && actionObj.cors) {
          hasCors = true;
          corsDomain = actionObj.cors.domain || '*';
          corsCredentials = actionObj.cors.credentials || false;
          if (actionObj.cors.methods) {
            corsMethods = actionObj.cors.methods;
          }
        }
        if (hasCors) {
          if (!corsMethods) {
            corsMethods = CORS_METHODS.concat([]);
          } else if (corsMethods.indexOf('OPTIONS') === -1) {
            corsMethods.push('OPTIONS');
          }
          try {
            res.header('Access-Control-Allow-Origin', corsDomain);
            res.header('Access-Control-Allow-Methods', corsMethods.join(', '));
            res.header('Access-Control-Allow-Credentials', corsCredentials);
            res.header('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || '*');
            res.header('Access-Control-Max-Age', (this.#config.corsAge || 600).toString());
          } catch (e) {
          }
        }
        let resultHeaders = intentObj.resultHeaders();
        if (resultHeaders && !res.headersSent) {
          Object.keys(resultHeaders).forEach((name) => {
            if (this.#config.ignoreHeaders && this.#config.ignoreHeaders.indexOf(name) !== -1) return;
            let value = resultHeaders[name];
            if (typeof value === 'string' || value instanceof Array || typeof value === 'number') {
              try {
                res.header(name, value);
              } catch (e) {
              }
            }
          });
        }
        let redirectTo = intentObj.redirectTo,
          redirectCode = intentObj.redirectCode;
        if (redirectTo) {
          // redirect the request.
          this.#handleIntentRedirect(req, res, intentObj, redirectTo, redirectCode);
          return;
        }
        let sendFn = (wasError ? this.#handleIntentError : this.#handleIntentSuccess);
        sendFn(req, res, next, data, intentObj);
      });
      if (req.filter) {
        intentObj.__setRawFilter(req.filter);
      }
      if (req.meta) {
        intentObj.__setRawMeta(req.meta);
      }
      intentObj.method = req.method;
      // IF we are coming from an alias, attach it.
      if (actionType !== req.action) {
        intentObj.match = req.action;
      }
      if (alias) {
        intentObj.alias = alias;
        intentObj.url = req.url;
      }
      /* Attach the result object if needed */
      if (actionObj.exposeRequest) {
        intentObj.req = req;
      }
      if (actionObj.exposeResponse) {
        intentObj.res = res;
      }
      // set up authorization information.
      let authToken = this.#getAuthorizationData(this.#config.authorization, req);
      if (authToken) {
        intentObj._setAuthorization('TOKEN', authToken);
      }
      intentObj.transport = 'http';
      // set up client information (headers, ip)
      const clientData = {
        ip: req.ip,
        headers: req.headers,
        xhr: req.xhr
      };
      if (req.geo) {
        clientData.geo = req.geo;
      }
      try {
        if (!clientData.xhr && req.headers.accept.indexOf('json') !== -1) {
          clientData.xhr = true;
        }
      } catch (e) {
      }
      intentObj.client(clientData);

      function onRequestClose() {
        if (isFinished) return;
        try {
          intentObj.__trigger(thorin.Intent.EVENT.CLOSE);
        } catch (e) {
        }
      }

      req.once('close', onRequestClose);
      thorin.dispatcher.triggerIntent(intentObj);
    }

    /**
     * Handle any kind of error.
     * */
    #handleRequestError = (err, req, res, next) => {
      // In order to make errors visible, we have to set CORS for em.
      let intentObj;
      if (req.intent) {
        intentObj = req.intent;
        delete req.intent;
      }
      this.#setCors(req, res);
      let reqErr,
        reqData,
        statusCode = 400;
      if (err instanceof SyntaxError) {  // any other error, we bubble up.
        reqErr = ERROR_PARSE;
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
          reqErr = ERROR_TOO_LARGE;
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
            reqErr = ERROR_ENCODING;
            break;
          case 400: // aborted
            reqErr = ERROR_ABORTED;
            break;
          case 413: // payload large
            reqErr = ERROR_TOO_LARGE;
            break;
          default:
            reqErr = thorin.error(err);
            reqErr.statusCode = 500;
        }
        reqData = {
          error: reqErr.toJSON()
        };
        statusCode = reqErr.statusCode;
      }
      try {
        res.status(statusCode);
      } catch (e) {
      }
      let logErr,
        logQs = this.#getShortQuery(req),
        rawUrl = this.#getShortUrl(req);
      // TODO: include the HTML 404 not found pages.
      if (req._hasDebug !== false) {
        let logMsg = '[ENDED',
          logLevel = 'trace';
        if (req.uniqueId) {
          logMsg += ' ' + req.uniqueId;
        }
        logMsg += '] -';
        if (req.action) logMsg += ' ' + req.action;
        logMsg += " (" + req.method.toUpperCase() + ' ' + rawUrl + ') ';
        logMsg += '= ' + statusCode + ' ';
        if (statusCode === 404) {
          if (reqErr.code !== ERROR_NOT_FOUND.code) {
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
        logger[logLevel](logMsg, logErr, logQs);
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
          res.end(err.rawData);
        } catch (e) {
          logger.error('Thorin.transport.http: failed to send error buffer to response.');
          logger.trace(e);
          try {
            res.end();
          } catch (e) {
          }
        }
        return;
      }
      if (typeof err.rawData === 'string') {
        try {
          res.type('html');
        } catch (e) {
        }
        try {
          res.end(err.rawData);
        } catch (e) {
          logger.error('Thorin.transport.http: failed to send error string to response.');
          logger.trace(e);
          try {
            res.end();
          } catch (e) {
          }
        }
        return;
      }
      try {
        if (req.exposeType === false && reqData.type) {
          delete reqData.type;
        }
        try {
          reqData = this.parseIntentJson(reqData, null, req, intentObj);
        } catch (e) {
        }
        res.header('content-type', 'application/json; charset=utf-8');
        reqData = JSON.stringify(reqData);
        res.end(reqData);
      } catch (e) {
        logger.error('Thorin.transport.http: failed to finalize request with error: ', reqErr);
        logger.error(e);
        try {
          res.end(reqErr.message);
        } catch (e) {
          try {
            res.end();
          } catch (e) {
          }
        }
      }
    }

    /**
     * Handles an intent redirect
     * */
    #handleIntentRedirect = (req, res, intentObj, redirectUrl, redirectCode) => {
      try {
        res.redirect(redirectCode, redirectUrl);
      } catch (e) {
        logger.warn(`Failed to perform redirect on action ${req.action}`, e);
      }
      let rawUrl = this.#getShortUrl(req),
        rawQs = this.#getShortQuery(req);
      if (req._hasDebug !== false) {
        let logMsg = '[ENDED ' + req.uniqueId + "] - ",
          took = Date.now() - req.startAt;
        logMsg += req.action + ' ';
        logMsg += "(" + req.method.toUpperCase() + ' ' + rawUrl + ') ';
        logMsg += '= ' + redirectCode + ' => ' + redirectUrl + ' ';
        logMsg += '(' + took + 'ms)';
        logger.trace(logMsg, rawQs);
      }
    }

    /**
     * Handles the actual success of the request's result.
     * */
    #handleIntentSuccess = (req, res, next, data, intentObj) => {
      let took = Date.now() - req.startAt,
        status = 200,
        isDone = false;
      /* IF we already have a status code, we just end the request right here. */
      try {
        if (typeof res.statusCode !== 'number') {
          res.status(status);
        }
        if (res.headersSent) {
          isDone = true;
        }
      } catch (e) {
      }

      if (isDone) {
        try {
          res.end();
        } catch (e) {
        }
      } else {
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
          res.send(data);
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
            logger.error('Thorin.transport.http: failed to send buffer to response.');
            logger.trace(e);
          }
        } else if (typeof data === 'object' && data != null) {
          try {
            if (typeof data.result === 'object' && data.result && typeof data.result.toJSON === 'function') {
              try {
                data.result = data.result.toJSON();
              } catch (e) {
              }
            }
            if (req.exposeType === false && data.type) {
              delete data.type;
            }
            try {
              data = this.parseIntentJson(null, data, req, intentObj);
            } catch (e) {
            }
            data = JSON.stringify(data);
            res.header('content-type', 'application/json');
            res.end(data);
          } catch (e) {
            logger.error('Thorin.transport.http: failed to handleIntentSuccess', e);
            try {
              res.end();
            } catch (e) {
            }
          }
        } else {
          res.end(data);
        }
      }
      if (req._hasDebug !== false) {
        let logMsg = '[ENDED ' + req.uniqueId + "] - ",
          rawUrl = this.#getShortUrl(req),
          rawQs = this.#getShortQuery(req);
        logMsg += req.action + ' ';
        logMsg += "(" + req.method.toUpperCase() + ' ' + rawUrl + ') ';
        logMsg += '= ' + status + ' ';
        logMsg += '(' + took + 'ms)';
        logger.trace(logMsg, rawQs);
      }

    }

    /**
     * Handles the actual error of the request's result.
     * */
    #handleIntentError = (req, res, next, data, intentObj) => {
      if (intentObj.hasRawResult()) {
        data.rawData = intentObj.result();
      }
      req.intent = intentObj;
      return this.#handleRequestError(data, req, res, next);
    }

    /**
     * Given a req object, it will return the raw url, with no qs.
     * */
    #getShortUrl = (req) => {
      let url = req.originalUrl || req.url;
      if (!url) return '';
      let qIdx = url.indexOf('?');
      if (qIdx !== -1) {
        url = url.substr(0, qIdx);
      }
      return url;
    };

    /**
     * Given a request, it checks if it has a query obj, not-null.
     * */
    #getShortQuery = (req) => {
      if (typeof req.query !== 'object' || !req.query) return;
      let qKeys = Object.keys(req.query);
      if (qKeys.length === 0) return;
      try {
        return JSON.stringify(req.query);
      } catch (e) {}
    };

  }


  return ThorinExpress;
};
