# readability-js-api-client
A javascript api client lib for Readability

## License

MIT. [Read the LICENSE.md](LICENSE.md).

## Requirements

*  jQuery >= 2.1.0
*  jsSHA >= 1.6.0

## Usage

See sources in [example](test/index.html) for more details.

### Reader

```javascript
try {
    var client = new Readability.Reader(
        new Readability.Consumer('your-consumer-key', 'your-consumer-secret')
    );
    client.authorize('user-username', 'user-password')
        .then(function(token) {
            console.info('Authorized');
            console.log('Token' + token.getValue());
            console.log('Secret' + token.getSecret());
        }, function(response) {
            console.error('AUTH ERROR');
            console.log(response);
        })
        .then(function() {
            client.getBookmarks()
            .then(function(response) {
                console.info('SUCCESS');
                console.log(response);
            }, function(response) {
                console.error('ERROR');
                console.log(response);
            });
        });
} catch (e) {
    console.error('EXCEPTION');
    console.log(e);
}
```

### Parser

```javascript
try {
    var client = new Readability.Parser(
        new Readability.Consumer(bull, null, 'your-consumer-token')
    );
    client.parse('http://your-url.com')
        .then(function(response) {
            console.info('SUCCESS');
            console.log(response);
        }, function(response) {
            console.error('ERROR');
            console.log(response);
        });
} catch (e) {
    console.error('EXCEPTION');
    console.log(e);
}
```

### Shortener

```javascript
try {
    var client = new Readability.Shortener();
    client.create('http://your-url.com')
        .then(function(response) {
            console.info('SUCCESS');
            console.log(response);
        }, function(response) {
            console.error('ERROR');
            console.log(response);
        });
} catch (e) {
    console.error('EXCEPTION');
    console.log(e);
}
```