'use strict';
const cookie = require('cookie');
/**
 * Created by Adrian on 14-Apr-16.
 */
module.exports = function (thorin) {

  class ThorinIntent extends thorin.Intent {

    #redirectTo;
    #redirectCode;
    #cors;

    /**
     * Marks the current action as CORS
     * ARGUMENTS:
     *   - originDomain - if specified, work ONLY with the given domain.
     *   - options
     *       - credentials=false -> disables cookie sending
     * */
    hasCors() {
      if (typeof this.#cors === 'undefined' || this.#cors === false) return false;
      if (typeof this.#cors !== 'object' || !this.#cors) return false;
      return true;
    }

    /**
     * Returns an object of all the cookies found in the header.
     * */
    getCookies(name) {
      try {
        const h = this.client().headers || {};
        if (!h.cookie) {
          if (name) return null;
          return {};
        }
        const cookies = cookie.parse(h.cookie) || {};
        if (name) return cookies[name] ?? null;
        return cookies || {};
      } catch (e) {
        return {};
      }
    }

    getCors() {
      return this.#cors;
    }

    get redirectTo() {
      return this.#redirectTo || null;
    }

    get redirectCode() {
      return this.#redirectCode || 302;
    }

    cors(originDomain, opt) {
      this.#cors = {
        credentials: true
      };
      if (typeof originDomain === 'string') {  // remove any trailing /
        this.#cors.domain = originDomain;
      }
      if (typeof originDomain === 'object') {
        opt = originDomain;
        this.#cors = opt;
      } else if (typeof opt === 'object' && opt) {
        if (opt.credentials === false) {
          this.#cors.credentials = false;
        } else {
          this.#cors.credentials = true;
        }
      }
      return this;
    }

    /**
     * Checks if the current HTTP request is done via ajax.
     * */
    isAjax() {
      return this.client().xhr || false;
    }

    /**
     * Redirect the HTTP response to something else
     * */
    redirect(url, _code) {
      if (typeof url !== 'string' || !url) return this;
      if (typeof _code === 'number') {
        this.#redirectCode = _code;
      } else if (typeof _code === 'object' && _code) {
        // we have redirect with querystring
        let clean = [],
          keys = Object.keys(_code);
        for (let i = 0; i < keys.length; i++) {
          let k = keys[i];
          if (typeof _code[k] === 'undefined' || _code[k] == null) continue;
          clean[k] = _code[k];
        }
        try {
          let qstring = qs.stringify(clean);
          if (url.indexOf('?') === -1) {
            url += '?' + qstring;
          } else {
            url += '&' + qstring;
          }
        } catch (e) {
        }
      }
      this.#redirectTo = url;
      this._canRender = false;
      // IF code is set to false, we do not directly send()
      if (_code === false) {
        return this;
      }
      return this.send();
    }

  }

  thorin.Intent = ThorinIntent;

};
