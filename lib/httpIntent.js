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
    hasCors() {
      if (typeof this[cors] === 'undefined' || this[cors] === false) return false;
      if (typeof this[cors] !== 'object' || !this[cors]) return false;
      return true;
    }

    getCors() {
      return this[cors];
    }

    cors(originDomain, opt) {
      this[cors] = {
        credentials: true
      };
      if (typeof originDomain === 'string') {  // remove any trailing /
        this[cors].domain = originDomain;
      }
      if (typeof originDomain === 'object') {
        opt = originDomain;
        this[cors] = opt;
      } else if (typeof opt === 'object' && opt) {
        if (opt.credentials === false) {
          this[cors].credentials = false;
        } else {
          this[cors].credentials = true;
        }
      }
      return this;
    }

    /*
     * Checks if the current HTTP request is done via ajax.
     * */
    isAjax() {
      return this.client().xhr || false;
    }
  }

  thorin.Intent = ThorinIntent;

};