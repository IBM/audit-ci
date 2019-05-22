module.exports = `/usr/local/lib/node_modules/yarn/lib/cli.js:66237
            throw new (_errors || _load_errors()).ResponseError(_this3.reporter.lang('requestFailed', description), res.statusCode);
            ^
Error: Request failed "503 Service Unavailable"
    at ResponseError.ExtendableBuiltin (/usr/local/lib/node_modules/yarn/lib/cli.js:702:66)
    at new ResponseError (/usr/local/lib/node_modules/yarn/lib/cli.js:808:124)
    at Request.params.callback [as _callback] (/usr/local/lib/node_modules/yarn/lib/cli.js:66237:19)
    at Request.self.callback (/usr/local/lib/node_modules/yarn/lib/cli.js:129397:22)
    at Request.emit (events.js:193:13)
    at Request.<anonymous> (/usr/local/lib/node_modules/yarn/lib/cli.js:130369:10)
    at Request.emit (events.js:193:13)
    at IncomingMessage.<anonymous> (/usr/local/lib/node_modules/yarn/lib/cli.js:130291:12)
    at Object.onceWrapper (events.js:281:20)
    at IncomingMessage.emit (events.js:198:15)
Exiting...`;
