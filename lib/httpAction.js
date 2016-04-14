'use strict';
/**
 * Created by Adrian on 14-Apr-16.
 */
module.exports = function(thorin) {

  class ThorinAction extends thorin.Action {

    constructor(a,b,c) {
      super(a,b,c);
      this.defaultHandle = true;
    }

    /*
    * Marks the action to only be processed if coming from an alias.
    * */
    aliasOnly() {
      this.defaultHandle = false;
      return this;
    }

  };

  thorin.Action = ThorinAction;

};