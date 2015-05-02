/**
 * @package   Radio\Readability
 * @license   http://opensource.org/licenses/MIT  MIT license
 * @copyright 2015 Max Gopey (gopeyx@gmail.com)
 */

var Readability = {};
(function($, jsSHA){
    (function() {
        /**
         * Consumer representation.
         * @constructor
         */
        Readability.Consumer = function(_key, _secret, _token) {
            var key = _key,
                secret = _secret,
                token = _token;

            this.getKey = function() { return key; };
            this.getSecret = function() { return secret; };
            this.getToken = function() { return token; };

            this.setKey = function(_key) { key = _key; };
            this.setSecret = function(_secret) { secret = _secret; };
            this.setToken = function(_token) { token = _token; };

            return this;
        };
    })();

    (function() {
        /**
         * Token representation.
         * @constructor
         */
        Readability.Token = function(_value, _secret) {
            var value = _value,
                secret = _secret;

            this.getValue = function() { return value || ''; };
            this.getSecret = function() { return secret || ''; };

            this.setValue = function(_value) { value = _value; };
            this.setSecret = function(_secret) { secret = _secret; };

            return this;
        };
    })();

    (function() {
        /**
         * Simple Http Client using jQuery.ajax.
         * @constructor
         */
        Readability.HttpClient = function() {};
        Readability.HttpClient.prototype.request = function(url, method, params) {
            var headers = {};

            method = (method || 'GET').toUpperCase();
            params = params || {};

            if (method === 'POST') {
                headers['Content-Type'] = 'application/x-www-form-urlencoded';
            }
            if (method === 'DELETE') {
                var paramLines = [];
                for (var paramKey in params) if (params.hasOwnProperty(paramKey)) {
                    paramLines.push(paramKey + '=' + params[paramKey]);
                }
                url += (url.indexOf('?') >= 0 ? '&' : '?') + paramLines.join('&');
                params = {};
            }

            var requestParams = {
                data: params,
                method: method,
                headers: headers
            };
            if (method == 'HEAD') {
                var defer = $.Deferred();
                requestParams.success = function(data, textStatus, response) {
                    defer.resolve(response);
                };
                requestParams.error = function(jqXHR, textStatus, errorThrown) {
                    defer.reject(errorThrown);
                };

                $.ajax(url, requestParams);

                return defer;
            } else {
                return $.ajax(url, requestParams);
            }
        };
        Readability.HttpClient.prototype.get = function(url, params) {
            return this.request(url, 'GET', params);
        };
        Readability.HttpClient.prototype.post = function(url, params) {
            return this.request(url, 'POST', params);
        };
        Readability.HttpClient.prototype.put = function(url, params) {
            return this.request(url, 'PUT', params);
        };
        Readability.HttpClient.prototype['delete'] = function(url, params) {
            return this.request(url, 'DELETE', params);
        };
        Readability.HttpClient.prototype.head = function(url, params) {
            return this.request(url, 'HEAD', params);
        };
    })();

    (function() {
        /**
         * XAuth Http Client.
         * @constructor
         */
        Readability.xAuthClient = function(_consumer, _token) {
            this.consumer = _consumer;
            this.token = _token || new Readability.Token();
        };

        Readability.xAuthClient.prototype = new Readability.HttpClient();
        Readability.xAuthClient.prototype.constructor = Readability.xAuthClient;

        Readability.xAuthClient.prototype.authMethod = 'POST';
        Readability.xAuthClient.prototype.defaultParams = {
            oauth_consumer_key: null,
            oauth_signature_method: 'HMAC-SHA1',
            oauth_timestamp: null,
            oauth_nonce: null,
            oauth_token: null,
            oauth_version: '1.0'
        };

        Readability.xAuthClient.prototype._parent_request = Readability.HttpClient.prototype.request;
        Readability.xAuthClient.prototype.request = function(url, method, params) {
            var paramsWithAuth = this.enrichParams(params || {}, url, method || 'GET');
            return this._parent_request(url, method, paramsWithAuth)
        };

        Readability.xAuthClient.prototype.enrichParams = function(params, url, method) {
            for (var paramKey in this.defaultParams) if (this.defaultParams.hasOwnProperty(paramKey)) {
                if (params[paramKey] === undefined) {
                    params[paramKey] = this.defaultParams[paramKey];
                }
            }
            params['oauth_consumer_key'] = this.consumer.getKey();
            params['oauth_timestamp'] = Date.now() / 1000 | 0;
            params['oauth_nonce'] = generateNonce(6);
            params['oauth_token'] = this.token.getValue();
            params['oauth_signature'] = this.getSignature(url, method, params);

            return params;
        };

        Readability.xAuthClient.prototype.getSignature = function(url, method, params) {
            var baseString = this.buildSignatureBaseString(url, method, params);
            var signingKey = this.buildSigningKey();
            var shaObj = new jsSHA(baseString, "TEXT");
            var signature = shaObj.getHMAC(signingKey, "TEXT", "SHA-1", "HEX");
            return btoa(hex2bin(signature));
        };

        Readability.xAuthClient.prototype.buildSignatureBaseString = function (url, method, params) {
            url = url.replace('http://readability.me/readability-js-api-client/test/api-proxy.php', 'https://readability.com/api');
            var baseString = method.toUpperCase() + '&' + encodeURIComponent(url) + '&';
            var encodedParams = [];
            for (var paramKey in params) if (params.hasOwnProperty(paramKey)) {
                var encodedKey = encodeURIComponent(paramKey);
                encodedParams.push({
                    key: encodedKey,
                    line: encodedKey + '=' + encodeURIComponent(params[paramKey])
                });
            }
            encodedParams.sort(function(a, b) {
                if (a.key < b.key) {
                    return -1;
                } else if (a.key > b.key) {
                    return 1;
                }
                return 0;
            });
            baseString += encodeURIComponent(encodedParams.map(function(param) {
                return param.line;
            }).join('&'));

            return baseString;
        };

        Readability.xAuthClient.prototype.buildSigningKey = function() {
            return encodeURIComponent(this.consumer.getSecret()) +
                '&' + encodeURIComponent(this.token.getSecret());
        };

        Readability.xAuthClient.prototype.getXauthParams = function(username, password) {
            return {
                x_auth_username: username,
                x_auth_password: password,
                x_auth_mode: 'client_auth'
            };
        };

        Readability.xAuthClient.prototype.getToken = function(authUrl, username, password) {
            var defer = $.Deferred();
            var params = this.getXauthParams(username, password);
            var client = this;
            this.request(authUrl, this.authMethod, params).then(function(response) {
                var oauthToken = getParameterByName('oauth_token', '&' + response);
                var oauthTokenSecret = getParameterByName('oauth_token_secret', '&' + response);

                if (oauthToken && oauthTokenSecret) {
                    var token = new Readability.Token(oauthToken, oauthTokenSecret);
                    client.setToken(token);
                    defer.resolve(token);
                } else {
                    defer.reject(response);
                }
            }, function(response) {
                defer.reject(response);
            });

            return defer;
        };

        Readability.xAuthClient.prototype.setToken = function(_token) {
            this.token = _token;
        };

        function generateNonce(length) {
            length = length || 5;
            var possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            for (var text = '', i = 0; i < length; i++) {
                text += possible.charAt(Math.floor(Math.random() * possible.length));
            }
            return text;
        }

        function getParameterByName(name, query) {
            name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
            var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
                results = regex.exec(query);
            return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
        }

        function hex2bin(hex) {
            var bytes = [];
            for (var i = 0; i < hex.length - 1; i += 2) {
                bytes.push(parseInt(hex.substr(i, 2), 16));
            }
            return String.fromCharCode.apply(String, bytes);
        }
    })();

    (function() {
        /**
         * Abstract Readability Client.
         * @constructor
         */
        Readability.AbstractClient = function() {
            this.httpClient = new Readability.HttpClient();
            this.apiUrl = 'https://readability.com/api';
            // for testing only:
            this.apiUrl = 'http://readability.me/readability-js-api-client/test/api-proxy.php';
            this.apiPath = '';
        };

        Readability.AbstractClient.prototype.getUrl = function(resource) {
            return this.apiUrl + this.apiPath + '/' + resource;
        };

        Readability.AbstractClient.buildResponse = function(rawResponse) {
            var responseData = $.parseJSON(rawResponse);
            if (responseData) {
                return responseData;
            } else {
                throw {message: 'Request was successful but response is malformed.'};
            }
        };
        Readability.AbstractClient.prototype.getDoneCallback = function (defer) {
            return function(response) {
                try {
                    defer.resolve(Readability.AbstractClient.buildResponse(response));
                } catch (e) {
                    defer.reject(e);
                }
            };
        };

        Readability.AbstractClient.prototype.getFailCallback = function(defer) {
            return function(response) {
                defer.reject(response);
            };
        };
    })();

    (function() {
        /**
         * Readability Reader Client.
         * @constructor
         */
        Readability.Reader = function(consumer, token) {
            Readability.AbstractClient.apply(this, arguments);
            this.httpClient = new Readability.xAuthClient(consumer, token);
            this.apiPath = '/rest/v1';
        };

        Readability.Reader.prototype = new Readability.AbstractClient();
        Readability.Reader.prototype.constructor = Readability.Reader;

        Readability.Reader.prototype.setToken = function(token) {
            this.httpClient.setToken(token);
        };

        Readability.Reader.prototype.authorize = function(username, password) {
            return this.httpClient.getToken(this.getUrl('oauth/access_token'), username, password);
        };

        Readability.Reader.prototype.getResources = function() {
            var defer = $.Deferred();
            this.httpClient.get(this.getUrl(''))
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };

        Readability.Reader.prototype.getArticle = function(articleId) {
            var defer = $.Deferred();
            this.httpClient.get(this.getUrl('articles/' + articleId))
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };

        Readability.Reader.prototype.getBookmarks = function(parameters) {
            var defer = $.Deferred();
            this.httpClient.get(this.getUrl('bookmarks'), parameters)
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };

        Readability.Reader.prototype.addBookmark = function(url, favorite, archive, allowDuplicates) {
            var parameters = {
                url: url,
                favorite: favorite ? 1 : 0,
                archive: archive ? 1 : 0,
                allow_duplicates: allowDuplicates ? 1 : 0
            };
            return this.httpClient.post(this.getUrl('bookmarks'), parameters);
        };

        Readability.Reader.prototype.getBookmark = function(bookmarkId) {
            var defer = $.Deferred();
            this.httpClient.get(this.getUrl('bookmarks/' + bookmarkId))
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };

        Readability.Reader.prototype.updateBookmark = function(bookmarkId, parameters) {
            var defer = $.Deferred();
            if (typeof parameters['favorite'] !== 'undefined') {
                parameters['favorite'] = parameters['favorite'] ? 1 : 0;
            }
            if (typeof parameters['archive'] !== 'undefined') {
                parameters['archive'] = parameters['archive'] ? 1 : 0;
            }
            if (typeof parameters['read_percent'] !== 'undefined') {
                parameters['read_percent'] = parseFloat(parameters['read_percent']) || 0.0;
            }
            this.httpClient.post(this.getUrl('bookmarks/' + bookmarkId), parameters)
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };

        Readability.Reader.prototype.deleteBookmark = function(bookmarkId) {
            return this.httpClient.delete(this.getUrl('bookmarks/' + bookmarkId))
        };

        Readability.Reader.prototype.getBookmarkTags = function(bookmarkId) {
            var defer = $.Deferred();
            this.httpClient.get(this.getUrl('bookmarks/' + bookmarkId + '/tags'))
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };

        Readability.Reader.prototype.addBookmarkTags = function(bookmarkId, tags) {
            var defer = $.Deferred();
            var parameters = {tags: tags.join(',')};
            this.httpClient.post(this.getUrl('bookmarks/' + bookmarkId + '/tags'), parameters)
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };

        Readability.Reader.prototype.deleteBookmarkTag = function(bookmarkId, tagId) {
            return this.httpClient.delete(this.getUrl('bookmarks/' + bookmarkId + '/tags/' + tagId));
        };

        Readability.Reader.prototype.getTags = function() {
            var defer = $.Deferred();
            this.httpClient.get(this.getUrl('tags'))
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };

        Readability.Reader.prototype.getTag = function(tagId) {
            var defer = $.Deferred();
            this.httpClient.get(this.getUrl('tags/' + tagId))
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };

        Readability.Reader.prototype.deleteTag = function(tagId) {
            return this.httpClient.delete(this.getUrl('tags/' + tagId));
        };

        Readability.Reader.prototype.getUserInfo = function() {
            var defer = $.Deferred();
            this.httpClient.get(this.getUrl('users/_current'))
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };
    })();

    (function() {
        /**
         * Readability Parser Client.
         * @constructor
         */
        Readability.Parser = function(consumer) {
            if (!consumer) {
                throw {message: "Consumer instance with set token is required."};
            }
            Readability.AbstractClient.apply(this, arguments);
            this.consumer = consumer;
            this.apiPath = '/content/v1';
        };

        Readability.Parser.prototype = new Readability.AbstractClient();
        Readability.Parser.prototype.constructor = Readability.Parser;

        Readability.Parser.prototype.getAuthParams = function() {
            return {token: this.consumer.getToken()};
        };

        Readability.Parser.prototype.getResources = function() {
            var defer = $.Deferred();
            this.httpClient.get(this.getUrl(''), this.getAuthParams())
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };

        Readability.Parser.prototype.parse = function(url, articleId, maxPages) {
            var defer = $.Deferred();
            var parameters = this.getAuthParams();
            if (url) {
                parameters.url = url;
            }
            if (articleId) {
                parameters.id = articleId;
            }
            if (maxPages) {
                parameters.max_pages = maxPages;
            }
            this.httpClient.get(this.getUrl('parser'), parameters)
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };

        Readability.Parser.prototype.getStatus = function(url, articleId) {
            var defer = $.Deferred();
            var parameters = this.getAuthParams();
            if (url) {
                parameters.url = url;
            }
            if (articleId) {
                parameters.id = articleId;
            }

            this.httpClient.head(this.getUrl('parser'), parameters).then(function(response) {
                var articleId = response.getResponseHeader('X-Article-Id');
                var articleStatus = response.getResponseHeader('X-Article-Status');
                if (!articleId && articleStatus) {
                    defer.resolve({
                        id: articleId,
                        status: articleStatus
                    });
                }
                defer.reject({
                    message: 'Request was successful but status info is missing from headers.'
                });
            }, this.getFailCallback(defer));

            return defer;
        };

        Readability.Parser.prototype.getConfidence = function(url) {
            var defer = $.Deferred();
            this.httpClient.get(this.getUrl('confidence'), {url: url})
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };
    })();

    (function() {
        /**
         * Readability Shortener Client.
         * @constructor
         */
        Readability.Shortener = function() {
            Readability.AbstractClient.apply(this, arguments);
            this.apiPath = '/shortener/v1';
        };

        Readability.Shortener.prototype = new Readability.AbstractClient();
        Readability.Shortener.prototype.constructor = Readability.Shortener;

        Readability.Shortener.prototype.getResources = function() {
            var defer = $.Deferred();
            this.httpClient.get(this.getUrl(''))
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };

        Readability.Shortener.prototype.create = function(url) {
            var defer = $.Deferred();
            this.httpClient.post(this.getUrl('urls'), {url: url})
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };

        Readability.Shortener.prototype.get = function(urlId) {
            var defer = $.Deferred();
            this.httpClient.get(this.getUrl('urls/' + urlId))
                .then(this.getDoneCallback(defer), this.getFailCallback(defer));
            return defer;
        };
    })();
})(jQuery, jsSHA);