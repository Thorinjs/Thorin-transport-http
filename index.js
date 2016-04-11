'use strict';
const http = require('http'),
  path = require('path');

const expressAppLoader = require('./lib/app');

/**
 * Created by Adrian on 29-Mar-16.
 */
module.exports = function init(thorin) {
  const async = thorin.util.async;
  const ExpressApp = expressAppLoader(thorin);
  const config = Symbol(),
    running = Symbol(),
    middleware = Symbol(),
    app = Symbol();

  class http extends thorin.Interface.Transport {
    static publicName() { return "http"; }

    constructor() {
      super();
      this.name = 'http';
      this[running] = false;
      this[middleware] = [];  // additional middleware to use.
      this[config] = {};
      this[app] = null;
    }
    get app() {
      if(!this[app]) return null;
      return this[app];
    }

    /*
    * Initializes the transport with config.
    * */
    init(httpConfig) {
      this[config] = thorin.util.extend({
        debug: true,
        port: 3000,
        basePath: '/',
        actionPath: '/handle', // this is the default frux listener for incoming frux actions.
        authorization: {
          "header": "Authorization"  // By default, we will look into the "Authorization: Bearer" header
          //"cookie": "tps"
        },
        ip: '0.0.0.0',
        cors: false,  // Cross origin requests. If set a string, we'll use the domain as the origin, or an array of domains.
        trustProxy: true, // be default, we trust the X-Forwarded-For header.
        static: path.normalize(thorin.root + '/public'),       // static path
        options: {
          payloadLimit: 50000 // maximum amount of string to process with json
        }
      }, httpConfig);
      this[app] = new ExpressApp(this[config], this._log.bind(this));
      for(let i=0; i < this[middleware].length; i++) {
        this[app]._addMiddleware(this[middleware][i]);
      }
      this[middleware] = [];
    }

    /*
    * Runs the HTTP Server and binds it to the port.
    * */
    run(done) {
      this.app.listen((e) => {
        if(e) return done(e);
        thorin.dispatcher.registerTransport(this);
        done();
      });
    }
    /* Manually add an express middleware. */
    addMiddleware(fn) {
      if(!this[app]) {
        this[middleware].push(fn);
        return this;
      }
      if(this.app.running) {
        console.error('Thorin.transport.http: addMiddleware() must be called before the app is running.');
        return this;
      }
      if(typeof fn !== 'function') {
        console.error('Thorin.transport.http: addMiddleware(fn) must be called with a function.');
        return this;
      }
      this.app._addMiddleware(fn);
    }

    /*
    * Registers an incoming intent action.
    * HTTP Actions work with aliases.
    * */
    routeAction(actionObj) {
      this.app.addHandler(actionObj);
      for(let i=0; i < actionObj.aliases.length; i++) {
        let alias = actionObj.aliases[i];
        if(typeof alias.verb !== 'string') {
          console.error('Thorin.transport.http: action ' + actionObj.name + ' alias ' + alias.name + ' does not have a HTTP verb');
          continue;
        }
        this.app.addHandler(actionObj, alias.verb, alias.name);
      }
    }

    /*
    * Temporary disable the action from being processed.
    * */
    disableAction(actionName) {
      this.app.disableHandler(actionName);
      return this;
    }

    /* Re-enables the action to be processed. */
    enableAction(actionName) {
      this.app.enableHandler(actionName);
      return this;
    }

    /*
    * This will handle the transport logger.
    * */
    _log() {
      if(this[config].debug === false) return;
      let logObj = thorin.logger(this.name);
      logObj.log.apply(logObj, arguments);
    }
  }

  return http;
};