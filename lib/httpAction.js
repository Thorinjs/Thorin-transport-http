'use strict';
/**
 * Created by Adrian on 14-Apr-16.
 */
module.exports = function(thorin) {

  class ThorinAction extends thorin.Action {

    constructor(a,b,c) {
      super(a,b,c);
      this.defaultHandle = true;
      this.cors = false;
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
      if(typeof originDomain === 'string') {  // remove any trailing /
        let tmp = originDomain.split('//'),
          corsDomain = tmp[0] + '//';
        tmp[1] = tmp[1].split('/')[0];
        corsDomain += tmp[1];
        this.cors.domain = corsDomain;
      }
      if(typeof originDomain === 'object') opt = originDomain;
      if(typeof opt === 'object' && opt) {
        if(opt.credentials === false) {
          this.cors.credentials = false;
        } else {
          this.cors.credentials = true;
        }
      }
      return this;
    }

  };

  thorin.Action = ThorinAction;

};