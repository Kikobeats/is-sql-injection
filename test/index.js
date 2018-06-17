'use strict'

const test = require('ava')

const isSQLInjection = require('..')

test('Detection of SQL meta-characters', t => {
  const input =
    'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQL Injection - Paranoid"; flow:to_server,established;uricontent:".pl";pcre:"/(%27)|(\')|(--)|(%23)|(#)/i"; classtype:Web-application-attack; sid:9099; rev:5;)'
  t.is(isSQLInjection(input), true)
})
