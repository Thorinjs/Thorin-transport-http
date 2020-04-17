'use strict';
const initHttp = require('./lib/httpTransport'),
  initAction = require('./lib/httpAction'),
  initIntent = require('./lib/httpIntent');

/**
 * Thorin.js HTTP Transport
 */
module.exports = function init(thorin, opt) {
  initAction(thorin);
  initIntent(thorin);
  const HttpTransport = initHttp(thorin, opt);

  return HttpTransport;
};
module.exports.publicName = 'http';
