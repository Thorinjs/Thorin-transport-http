'use strict';
/**
 * This is our Thorin transport class.
 * */
const expressAppLoader = require('./app'),
  path = require('path'),
  cookie = require('cookie'),
  helmet = require('helmet');
const SETUP_DIRECTORIES = [
  'app/actions',
  'app/middleware'
];
module.exports = function init(app) {
  const logger = app.logger('http');
  const ExpressApp = expressAppLoader(app, logger);


  class ThorinTransportHttp extends app.Interface.Transport {
    static publicName() {
      return "http";
    }

    get cookie() {
      return cookie;
    }

    set cookie(v) {}

    get helmet() {
      return helmet;
    }

    set helmet(v) {}

    #middleware = [];  // additional middleware to use.
    #config = {};
    #app = null;

    constructor(cfg, app, name) {
      super();
      this.name = (typeof name === 'string' && name ? name : 'http');
      logger.name = this.name;
    }

    /**
     * Initializes the transport with config.
     * */
    init(httpConfig) {
      this.#config = app.util.extend({
        debug: true,
        port: 3000,
        basePath: '/',
        actionPath: '/dispatch', // this is the default frux listener for incoming frux actions.
        authorization: {
          "header": "Authorization",  // By default, we will look into the "Authorization: Bearer" header
          "basic": null   // if set to {user,password}, we will apply basic authorization for it. This can be used for fast prototyping of password protected apps.
          //"cookie": "tps"
        },
        ip: '0.0.0.0',
        cors: false,  // Cross origin requests. If set a string, we'll use the domain as the origin, or an array of domains.
        corsIgnore: null, // If specified, we will ignore these hosts in CORS requests. Array or string
        corsAge: 600,     // the CORS max-age
        trustProxy: true, // be default, we trust the X-Forwarded-For header.
        static: path.normalize(app.root + '/public'),       // static path
        options: {
          payloadLimit: 100000 // maximum amount of string to process with json
        },
        ignoreHeaders: null,  // An array of ignored HTTP Headers.
        hideType: false,  // If set to true, hide the "type" field in the result object
        rawText: false,   // If set to true, we will parse raw text/plain POST requests and place the text under intentObj.rawInput._text
        helmet: {   // Default helmet configuration, for full config, see https://github.com/helmetjs/helmet
          frameguard: false,
          contentSecurityPolicy: {
            browserSniff: true,
            disableAndroid: false,
            setAllHeaders: false,
            directives: {
              objectSrc: ["'none'"],
              workerSrc: null  // This is not set.
            }
          },
          dnsPrefetchControl: {
            allow: false
          },
          hsts: false,
          ieNoOpen: true,
          noCache: false,
          hpkp: false
        }
      }, httpConfig);
      if (typeof this.#config.actionPath === 'string') {
        this.#config.actionPath = [this.#config.actionPath];
      }
      app.config.set('transport.' + this.name, this.#config);  // update the app with the full config
      logger.setLevels(this.#config.debug);
      this.#app = new ExpressApp(this.#config, logger);
      for (let i = 0; i < this.#middleware.length; i++) {
        this.#app._addMiddleware(this.#middleware[i]);
      }
      this.#middleware = [];
    }

    get running() {
      if (!this.#app) return false;
      return this.#app.running;
    }

    get app() {
      if (!this.#app) return null;
      return this.#app;
    }

    /**
     * Manually return the configuration object of the transport.
     * */
    getConfig() {
      return this.#config;
    }

    /**
     * Checks if we trust a reverse proxy or not
     * */
    trustProxy() {
      return this.#config.trustProxy;
    }

    /**
     * Override the default API intent response structure. By default,
     * we have a "type":{actionName}, "result": {object}.
     * Note: this should not be used other than to offer backwards-compatibility
     * */
    _handleIntentJson(fn) {
      if (!this.#app) {
        logger.warn('handleIntentJson: app is not started yet.');
        return false;
      }
      if (typeof fn !== 'function') {
        logger.error(`handleIntentJson: callback is not a function`);
        return false;
      }
      this.#app.handleIntentJson(fn);
      return true;
    }

    /**
     * Sets up the directory structure of the project.
     * */
    setup(done) {
      for (let i = 0; i < SETUP_DIRECTORIES.length; i++) {
        try {
          app.util.fs.ensureDirSync(path.normalize(app.root + '/' + SETUP_DIRECTORIES[i]));
        } catch (e) {
        }
      }
      done();
    }

    /**
     * Runs the HTTP Server and binds it to the port.
     * */
    run(done) {
      this.#app.listen((e) => {
        if (e) return done(e);
        app.dispatcher.registerTransport(this);
        done();
      });
    }

    /** Manually add an express middleware. */
    addMiddleware(fn) {
      if (!this.#app) {
        this.#middleware.push(fn);
        return this;
      }
      if (this.#app.running) {
        logger.error('Thorin.transport.http: addMiddleware() must be called before the app is running.');
        return this;
      }
      if (typeof fn !== 'function') {
        logger.error('Thorin.transport.http: addMiddleware(fn) must be called with a function.');
        return this;
      }
      this.#app._addMiddleware(fn);
    }

    /**
     * Registers an incoming intent action.
     * HTTP Actions work with aliases.
     * */
    routeAction(actionObj) {
      if (!this.#app) return this;
      this.#app.addHandler(actionObj);
      for (let i = 0; i < actionObj.aliases.length; i++) {
        let alias = actionObj.aliases[i];
        if (typeof alias.verb !== 'string') {
          continue;
        }
        this.#app.addHandler(actionObj, alias.verb, alias.name);
      }
      return this;
    }

    /**
     * Temporary disable the action from being processed.
     * */
    disableAction(actionName) {
      if (!this.#app) return this;
      this.#app.disableHandler(actionName);
      return this;
    }

    /**
     * Re-enables the action to be processed.
     *  */
    enableAction(actionName) {
      if (!this.#app) return this;
      this.#app.enableHandler(actionName);
      return this;
    }

    /**
     * This will handle the transport logger.
     * @Deprecated
     * */
    _log() {
      return logger.call(logger, [...arguments]);
    }
  }

  return ThorinTransportHttp;
};
