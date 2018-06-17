'use strict'

/**
 * SQL regex reference - taken from symantec
 * http://www.symantec.com/connect/articles/detection-sql-injection-and-cross-site-scripting-attacks
 */

const sql = new RegExp("w*((%27)|('))((%6F)|o|(%4F))((%72)|r|(%52))", 'i')

const sqlMeta = new RegExp("(%27)|(')|(--)|(%23)|(#)", 'i')

/* eslint-disable */
const sqlMetaVersion2 = new RegExp(
  "(()|(=))[^\n]*((%27)|(')|(--)|(%3B)|(;))",
  'i'
)
/* eslint-enable */

const sqlUnion = new RegExp("((%27)|('))union", 'i')

module.exports = value =>
  sql.test(value) ||
  sqlMeta.test(value) ||
  sqlMetaVersion2.test(value) ||
  sqlUnion.test(value)
