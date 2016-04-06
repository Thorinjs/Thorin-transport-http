'use strict';
const async = require('async'),
  http = require('http'),
  path = require('path');

const expressAppLoader = require('./lib/app');

/**
 * Created by Adrian on 29-Mar-16.
 */
module.exports = function init(thorin) {
  const ExpressApp = expressAppLoader(thorin);
  const config = Symbol(),
    running = Symbol(),
    app = Symbol();

  class http extends thorin.Interface.Transport {
    static publicName() { return "http"; }

    constructor() {
      super();
      this.name = 'http';
      this[running] = false;
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
        port: 3000,
        basePath: '/',
        actionPath: '/handle', // this is the default frux listener for incoming frux actions.
        authorization: {
          source: 'header',  // WHERE to look for the authorization Values are: header, cookies
          name: 'Authorization' // WHICH one to fetch from there.
        },
        ip: '0.0.0.0',
        cors: false,  // Cross origin requests. If set a string, we'll use the domain as the origin, or an array of domains.
        trustProxy: true, // be default, we trust the X-Forwarded-For header.
        static: path.normalize(thorin.root + '/public'),       // static path
        options: {
          payloadLimit: 50000 // maximum amount of string to process with json
        }
      }, httpConfig);
      this[app] = new ExpressApp(this[config]);
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
  }

  return http;
};