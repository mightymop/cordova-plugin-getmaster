var exec = require('cordova/exec');
var PLUGIN_NAME = 'getmaster';

var getmaster = {

	get : function (val, success, error ) {
		exec(success, error, PLUGIN_NAME, 'get', [val]);
	}
};

module.exports = getmaster;
