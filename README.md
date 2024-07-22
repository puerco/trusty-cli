# Trusty CLI

A utility to do useful stuff with trusty data. 

This tool collects POCs of applications that leverage Trusty data to supply chain
technologies. 

⚠️ _Alpha Notice:_ ⚠️ This project is not yet meant to be stable. All output
and command line params are subject to change without notice.

## Usage

```
A CLI utility to do useful stuff with Trusty data. 

Usage:
  trusty [command]

Available Commands:
  attest      generate Trusty attestations from source code
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  sbom        report dependency quality from an SBOM
  version     Prints the version

Flags:
  -h, --help               help for trusty
      --log-level string   the logging verbosity, either 'panic', 'fatal', 'error', 'warning', 'info', 'debug', 'trace' (default "info")

Use "trusty [command] --help" for more information about a command.

```


## Attest Trusty Data

The Trusty CLI can generate attestations capturing the scores of the dependencies
of a project. Attestations can be signed and bundled in sigstore bundle. 

## SBOM Analysis 

The CLI tool can read SBOMs and report data on dependencies found in the document.
The Trust CLI can export quality data to CSV files for further analysis in other
tools.

