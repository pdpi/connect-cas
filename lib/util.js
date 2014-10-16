var qs = require('querystring');
var url = require('url');

module.exports.origin = function(req){

    var configuration = require('./configure')();
    if (configuration.service) {
      return configuration.service;
    }

    var query = req.query;
    var parsedUrl = url.parse(req.url);
    if (query.ticket) delete query.ticket;
    var querystring = qs.stringify(query);
    var protocol = req.headers['x-forwarded-proto'];
    console.log(protocol);
    var path = parsedUrl.pathname
    var orig = protocol + '://' + req.headers.host + path + (querystring ? '?' + querystring : '');
    console.log(orig);
    return orig;
};