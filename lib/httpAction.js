'use strict';
/**
 * Created by Adrian on 14-Apr-16.
 */
module.exports = function (thorin) {

  const closes = Symbol();

  class ThorinAction extends thorin.Action {

    constructor(a, b, c) {
      super(a, b, c);
      this.defaultHandle = true;
      this.cors = false;
    }

    /*
     * Exposes the internal express request object
     * */
    exposeReq() {
      this.exposeRequest = true;
      return this;
    }

    /*
     * Exposes the internal express response
     * */
    exposeRes() {
      this.exposeResponse = true;
      return this;
    }

    /*
     * Marks the action to only be processed if coming from an alias.
     * */
    aliasOnly() {
      this.defaultHandle = false;
      return this;
    }

    /*
     * Marks the current action as CORS
     * ARGUMENTS:
     *   - originDomain - if specified, work ONLY with the given domain.
     *   - options
     *       - credentials=false -> disables cookie sending
     * */
    enableCors(originDomain, opt) {
      this.cors = {
        credentials: true
      };
      if (typeof originDomain === 'string') {  // remove any trailing /
        let corsDomain;
        if (originDomain.indexOf('://') !== -1) {
          let tmp = originDomain.split('//');
          corsDomain = tmp[0] + '//';
          tmp[1] = tmp[1].split('/')[0];
          corsDomain += tmp[1];
        } else {
          corsDomain = originDomain.split('/')[0];
        }
        this.cors.domain = corsDomain;
      }
      if (typeof originDomain === 'object') opt = originDomain;
      if (typeof opt === 'object' && opt) {
        if (opt.credentials === false) {
          this.cors.credentials = false;
        } else {
          this.cors.credentials = true;
        }
      }
      return this;
    }

  }

  thorin.Action = ThorinAction;

};