//
// For debugging purposes only. (Will probably delete this in future.)
// See also helpers.readRegoAnnotations in antora/ec-policies-antora-extension/index.js
//
const glob = require("glob")

const opa = require("@zregvart/opa-inspect")
//const opa = require("../../../opa-inspect-js/index.js")

function inspectAllRego(globPattern) {
  return glob.sync(globPattern).map(opa.inspect)
}

function readRegoAnnotations() {
  // Flatten because otherwise we get a separate list for each file
  return Promise.all(inspectAllRego("policy/**/*.rego")).then(a => a.flat())
}

async function main() {
  const allAnnotations = await readRegoAnnotations()
  // Filter to remove rules with no annotations
  console.log(JSON.stringify(allAnnotations.filter(a => a.annotations)))
}

main()
