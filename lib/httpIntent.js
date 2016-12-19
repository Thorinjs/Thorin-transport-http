'use strict';
/**
 * Created by Adrian on 14-Apr-16.
 */
module.exports = function (thorin) {

  const cors = Symbol();

  class ThorinIntent extends thorin.Intent {

    /*
     * Marks the current action as CORS
     * ARGUMENTS:
     *   - originDomain - if specified, work ONLY with the given domain.
     *   - options
     *       - credentials=false -> disables cookie sending
     * */
    cors(originDomain, opt) {
      this.cors = {
        credentials: true
      };
      if (typeof originDomain === 'string') {  // remove any trailing /
        this.cors.domain = originDomain;
      }
      if (typeof originDomain === 'object') {
        opt = originDomain;
        this.cors = opt;
      } else if (typeof opt === 'object' && opt) {
        if (opt.credentials === false) {
          this.cors.credentials = false;
        } else {
          this.cors.credentials = true;
        }
      }
      return this;
    }
  }

  thorin.Intent = ThorinIntent;

};