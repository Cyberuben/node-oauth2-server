'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('../errors/invalid-argument-error');

/**
 * Constructor.
 */

function BearerTokenType(accessToken, accessTokenLifetime, refreshToken, scope, customAttributes) {
  if (!accessToken) {
    throw new InvalidArgumentError('Missing parameter: `accessToken`');
  }

  this.accessToken = accessToken;
  this.accessTokenLifetime = accessTokenLifetime;
  this.refreshToken = refreshToken;
  this.scope = scope;

  if (customAttributes) {
    this.customAttributes = customAttributes;
  }
}

/**
 * Retrieve the value representation.
 */

BearerTokenType.prototype.valueOf = function() {
  var object = {
    accessToken: this.accessToken,
    tokenType: 'Bearer'
  };

  if (this.accessTokenLifetime) {
    object.expiresIn = this.accessTokenLifetime;
  }

  if (this.refreshToken) {
    object.refreshToken = this.refreshToken;
  }

  if (this.scope) {
    object.scope = this.scope;
  }

  for (var key in this.customAttributes) {
    if (this.customAttributes.hasOwnProperty(key)) {
      object[key] = this.customAttributes[key];
    }
  }
  return object;
};

/**
 * Export constructor.
 */

module.exports = BearerTokenType;
