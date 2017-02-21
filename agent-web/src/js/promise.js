/** 
 * @classdesc Implementation of Promise, because as we do not know a library that will be used for development can not depend on any. 
 * @class
 */
var Promise = (function() {
    var callback = null;

	/**
	 * Then method to use um finish.
	 * @param {function} cb - Callback to use on finish.
	 * @memberof Promise
	 */
    this.then = function(cb) {
        callback = cb;
    };

	/**
	 * Resolve method to us on resolve event.
	 * @param {object} value - Value to send a callback setted on Then.
	 * @memberof Promise
	 */
    this.resolve = function(value) {
        callback(value);
    };
    
});
