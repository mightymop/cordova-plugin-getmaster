var exec = require('cordova/exec');
var PLUGIN_NAME = 'getmaster';

var getmaster = {
	
	getUserSecret : function (user, success, error ) {
		exec(success, error, PLUGIN_NAME, 'getUserSecret', [user]);
	},
	init: function (val, success, error ) {
		exec(success, error, PLUGIN_NAME, 'init', [val]);
	}
};

module.exports = getmaster;
