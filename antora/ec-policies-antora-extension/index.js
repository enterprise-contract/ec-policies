'use strict'

// Helpers for handlebars templates
const hbsHelpers = {

  // Convert "foo" to "FOO"
  toUpper: (s) => {
    return s.toUpperCase()
  },

  // Convert "foo bar" to "Foo bar"
  sentenceCase: (s) => {
    return s.charAt(0).toUpperCase() + s.slice(1)
  },

  // Convert "foo_bar" to "foo bar"
  toWords: (s) => {
    return s.replace(/_/g, " ")
  },

  // Convert "foo_bar" to "Foo bar"
  // (Prefer sentence case for titles, i.e. use "Foo bar" not "Foo Bar")
  toTitle: (s) => {
    return hbsHelpers.sentenceCase(hbsHelpers.toWords(s))
  },

  // Convert a repo name to its url
  repoUrl: (repoName) => {
    // quay.io does redirect from https://${repoName} but let's
    // be nice and set it to the actual preferred url
    const quayMatch = /^quay\.io/
    if (repoName.match(quayMatch)) {
      return `https://${repoName.replace(quayMatch, 'quay.io/repository')}`
    }
    else {
      // Todo: Check how well this works for other popular container
      // registries and maybe detect and set their preferred repo urls too
      return `https://${repoName}`
    }
  },

}

// General helpers
const helpers = {

  // https://github.com/you-dont-need/You-Dont-Need-Lodash-Underscore#_groupby
  groupBy: (xs, f) => {
    return xs.reduce((r, v, _i, _a, k = f(v)) => ((r[k] || (r[k] = [])).push(v), r), {})
  },

  // Find a data file and load its data
  dataFromAntoraFile: (yaml, moduleContent, fileName) => {
    // Assume there aren't multiple files with the same name
    const moduleFile = moduleContent.files.find(f => f.src.basename == fileName)
    if (!moduleFile) throw `Unable to find ${fileName} file in module: (${__filename})`
    // This works fine for both yaml and json
    return yaml.load(moduleFile._contents.toString())
  },

  toDottedPath: (path) => {
    return path.map(i => i.value).join(".")
  },

  // Extract useful fields and derived values from the raw data and collect
  // them for easy use in the template
  processAnnotationsData: (rawData, namespace) => {
    const output = []
    const packageAnnotations = {}

    // First pass to collect all the package annotations
    rawData.annotations.forEach((a) => {
      const fullPath = helpers.toDottedPath(a.path.slice(1))
      const inNamespace = fullPath.startsWith(namespace)
      const isPackageScope = a.annotations.scope == "package"

      if (inNamespace && isPackageScope) {
        // This doesn't handle the case where there are multiple entries
        // for the same package, so let's try to avoid that situation
        packageAnnotations[fullPath] = a.annotations
      }
    })

    // Now handle the rule annotations
    rawData.annotations.forEach((a) => {
      const fullPath = helpers.toDottedPath(a.path.slice(1))
      const inNamespace = fullPath.startsWith(namespace)
      const isRuleScope = a.annotations.scope == "rule"

      if (inNamespace && isRuleScope) {
        const isDeny = fullPath.endsWith(".deny")
        const isWarn = fullPath.endsWith(".warn")

        // Anything that isn't a top level rule doesn't get documented
        if (isDeny || isWarn) {
          const title = a.annotations.title
          const description = a.annotations.description
          const shortName = a.annotations.custom.short_name
          const warningOrFailure = isWarn ? "warning" : "failure"
          const failureMsg = a.annotations.custom.failure_msg
          const effectiveOn = a.annotations.custom.effective_on
          const file = a.location.file
          const row = a.location.row

          const packageShortName = a.path[3].value
          const packagePath = helpers.toDottedPath(a.path.slice(1, a.path.length-1))
          const pkgAnnotation = packageAnnotations[packagePath] || {}

          // If there is some package-scoped rule data then merge it in to the rule-scoped rule data
          var ruleData = a.annotations.custom.rule_data
          if (pkgAnnotation.custom && pkgAnnotation.custom[shortName] && pkgAnnotation.custom[shortName].rule_data) {
            ruleData = {...ruleData, ...pkgAnnotation.custom[shortName].rule_data}
          }

          // Also prepare some info about the package
          // (It's the same for every rule in a package, so it's not efficient to
          // redo this for every rule, but I don't think it will matter.)
          const packageInfo = {
            shortName: packageShortName,
            fullName: packagePath,
            title: pkgAnnotation.title || hbsHelpers.toTitle(packageShortName),
            description: pkgAnnotation.description || ""
          }

          output.push({
            fullPath, packagePath, packageInfo,
            shortName, title, description, ruleData, warningOrFailure,
            failureMsg, effectiveOn, file, row
          })
        }
      }
    })

    // Group the rules by their package
    return helpers.groupBy(output, a => a.packagePath)
  },

  processBundlesData: (rawData) => {
    const output = {}
    // For now we're only looking at the task-bundles since
    // the pipeline-bundles are not used in any of the policies
    const data = rawData["task-bundles"]

    Object.keys(data).forEach(k => {
      output[k] = data[k].map(d => {
        // Todo: These urls are quay.io specific and probably won't work
        // elsewhere. We should be able to provide the right urls for
        // other popular container registries.
        const repoUrl = hbsHelpers.repoUrl(k)
        const digestUrl = `${repoUrl}/manifest/${d.digest}`
        const tagUrl = `$(repoUrl)?tab=tags&tag=${d.tag}`
        const shortDigest = d.digest.split(":")[1].slice(0,12)

        return {
          ...d,
          digestUrl,
          tagUrl,
          shortDigest,
        }
      })
    })

    return output
  },

  // Convert modules/ROOT/templates/foo.hbs to modules/ROOT/pages/foo.adoc
  templateToPage: (path) => {
    return path.replace(/\/templates\//,'/pages/').replace(/\.hbs$/, '.adoc')
  },

  // Prepare data for adding a dynamic page to the pages list
  prepDynamicPage: (fileSrc, pageContent) => {
    const path = helpers.templateToPage(fileSrc.path)
    const abspath = helpers.templateToPage(fileSrc.abspath)
    const basename = helpers.templateToPage(fileSrc.basename)
    const contents = Buffer.from(pageContent)
    const stem = fileSrc.stem

    return {
      contents,
      path,
      src: {
        path,
        abspath,
        basename,
        stem,
        extname: '.adoc',
        // Related to the "Edit this page" link created by Antora
        origin: 'dynamic',
      }
    }
  },

}

module.exports.register = function() {
  this.on('contentAggregated', ({ contentAggregate }) => {
    // Skip modules other than the the ec-policies module
    contentAggregate.filter(c => c.name == 'ec-policies').forEach(content => {
      // Import yaml
      const yaml = this.require('js-yaml')

      // Find and load the two data files
      const rawAnnotationsData = helpers.dataFromAntoraFile(yaml, content, 'rule_annotations.json')
      const rawBundlesData = helpers.dataFromAntoraFile(yaml, content, 'acceptable_tekton_bundles.yml')

      // Massage the data so the templates can be clean and tidy
      const pipelineAnnotations = helpers.processAnnotationsData(rawAnnotationsData, "policy.pipeline")
      const releaseAnnotations = helpers.processAnnotationsData(rawAnnotationsData, "policy.release")
      const acceptableBundles = helpers.processBundlesData(rawBundlesData)

      // Import Handlebars and register helpers and partials
      const Handlebars = this.require('handlebars')
      Object.keys(hbsHelpers).forEach((k) => {
        Handlebars.registerHelper(k, hbsHelpers[k])
      })

      // Templates are in the templates directory
      // If they start with '_' they are treated as partials instead of pages
      const pageTemplatesMatch = /\/templates\/[a-z][a-z_]*\.hbs$/
      const partialTemplatesMatch = /\/templates\/_[a-z_]*\.hbs$/

      content.files.filter(f => f.path.match(partialTemplatesMatch)).forEach(f => {
        Handlebars.registerPartial(f.src.stem.replace(/^_/, ''), f._contents.toString())
      })

      // Dynamically generate pages/foo.adoc for any templates/foo.hbs file found
      // Note that every template gets all the data whether it wants it or not
      content.files.filter(f => f.path.match(pageTemplatesMatch)).forEach(f => {
        const hbsTemplate = Handlebars.compile(f._contents.toString())
        const generatedContent = hbsTemplate({ pipelineAnnotations, releaseAnnotations, acceptableBundles})
        content.files.push(helpers.prepDynamicPage(f.src, generatedContent))
      })
    })
  })
}
