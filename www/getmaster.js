var exec = require('cordova/exec');
var PLUGIN_NAME = 'getmaster';

var getmaster = {

	getUserSecrets : function (users, success, error ) {
		exec(success, error, PLUGIN_NAME, 'getUserSecrets', users);
	},
	init: function (success, error ) {
		exec(success, error, PLUGIN_NAME, 'init', []);
	}
};

module.exports = getmaster;
