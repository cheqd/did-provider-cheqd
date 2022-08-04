/**
 * @public
 */
// It can be disabled even not import statement is needed
// eslint-disable-next-line @typescript-eslint/no-var-requires
const schema = require('../plugin.schema.json')
export { schema }
export { CheqdDIDProvider } from './did-manager/cheqd-did-provider'
export { CheqdDidResolver, getResolver } from './did-manager/cheqd-did-resolver'
export { CheqdUniversalResolver } from './did-manager/resolver'
export { Cheqd } from './agent/ICheqd'
