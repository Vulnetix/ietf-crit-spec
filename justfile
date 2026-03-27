# Default draft source file
draft := "drafts/draft-vulnetix-crit-01.xml"
outdir := "build"
schema := "schemas/crit-dictionary-v0.2.0.schema.json"

# List available commands
default:
    @just --list

# Validate the XML by running preptool (catches errors without producing final output)
check:
    xml2rfc --preptool --out /dev/null {{draft}}

# Generate plain text output
text:
    mkdir -p {{outdir}}
    xml2rfc --text -o {{outdir}}/draft-vulnetix-crit-01.txt {{draft}}

# Generate HTML output
html:
    mkdir -p {{outdir}}
    xml2rfc --html -o {{outdir}}/draft-vulnetix-crit-01.html {{draft}}

# Generate both text and HTML
build: text html

# Run preptool to validate and prep the XML
prep:
    mkdir -p {{outdir}}
    xml2rfc --preptool -o {{outdir}}/draft-vulnetix-crit-01.prepped.xml {{draft}}

# Expand all references and output full XML
expand:
    mkdir -p {{outdir}}
    xml2rfc --expand -o {{outdir}}/draft-vulnetix-crit-01.exp.xml {{draft}}

# Update references to use bib.ietf.org
update-refs:
    xml2rfc --use-bib {{draft}}

# Validate dictionary JSON files against the CRIT dictionary schema
validate-dictionaries:
    check-jsonschema --schemafile {{schema}} dictionaries/*.json

# Check that (service, resource_type) is unique within each dictionary file
validate-dictionaries-unique-keys:
    #!/usr/bin/env sh
    fail=0
    for f in dictionaries/*.json; do
        dupes=$(jq -r '[.entries[] | "\(.service)/\(.resource_type)"] | group_by(.) | map(select(length > 1)) | .[][0]' "$f")
        if [ -n "$dupes" ]; then
            echo "ERROR: Duplicate (service, resource_type) in $f:"
            echo "$dupes"
            fail=1
        fi
    done
    exit $fail

# Run all validations (XML drafts + dictionary schema + uniqueness)
validate-all: check validate-dictionaries validate-dictionaries-unique-keys

# Run CRIT spec conformance tests (generates samples, runs all 45 rules, produces report)
test-spec:
    go run ./tests/cmd/crit-test --report tests/reports

# Validate CRIT-samples.json against its schema
test-validate-samples:
    check-jsonschema --schemafile schemas/crit-samples-v0.1.0.schema.json tests/CRIT-samples.json

# Validate hand-authored CRIT record samples against the record schema
test-validate-records:
    check-jsonschema --schemafile schemas/crit-record-v0.2.0.schema.json samples/**/*.json

# Validate CVE+CRIT data files against CVEListv5 format and CRIT spec rules
test-cve-crit:
    go run ./cmd/crit-validate --data data --report tests/reports

# Remove previous test report files
test-clean:
    rm -rf tests/reports

# Run full test suite: clean reports, run spec tests, validate schemas, validate CVE data
test: test-clean test-spec test-validate-samples test-validate-records test-cve-crit

# Download CVE records from cve.org and inject Vulnetix ADP container with x_crit data from samples
fetch-cve-data:
    #!/usr/bin/env sh
    set -e
    for sample in samples/**/*.json; do
        vid=$(jq -r '.vuln_id' "$sample")
        case "$vid" in CVE-*) ;; *) continue ;; esac
        year=$(echo "$vid" | sed 's/CVE-\([0-9]*\)-.*/\1/')
        dest="data/$year/$vid.json"
        if [ ! -f "$dest" ]; then
            mkdir -p "data/$year"
            echo "Downloading $vid..."
            curl -s "https://cveawg.mitre.org/api/cve/$vid" | jq '.' > "$dest"
        fi
    done
    echo "Injecting Vulnetix ADP containers..."
    for cve_file in data/**/*.json; do
        cve_id=$(jq -r '.cveMetadata.cveId' "$cve_file")
        # Skip if VVD ADP already present
        has_vvd=$(jq '[.containers.adp // [] | .[] | select(.providerMetadata.shortName == "VVD")] | length' "$cve_file")
        if [ "$has_vvd" -gt 0 ]; then
            echo "  $cve_id: VVD ADP already present, skipping"
            continue
        fi
        echo "[]" > /tmp/crit_records.json
        for sample in samples/**/*.json; do
            vid=$(jq -r '.vuln_id' "$sample" 2>/dev/null)
            if [ "$vid" = "$cve_id" ]; then
                jq --slurpfile rec "$sample" '. + $rec' /tmp/crit_records.json > /tmp/crit_tmp.json
                mv /tmp/crit_tmp.json /tmp/crit_records.json
            fi
        done
        count=$(jq 'length' /tmp/crit_records.json)
        jq --slurpfile crit /tmp/crit_records.json '.containers.adp = ((.containers.adp // []) + [{"providerMetadata":{"orgId":"8254265b-2729-46b6-b9e3-3dfca2d5bfca","shortName":"VVD"},"title":"Vulnetix Vulnerability Database Enrichment","x_crit":$crit[0]}])' "$cve_file" > "${cve_file}.tmp" && mv "${cve_file}.tmp" "$cve_file"
        echo "  $cve_id: $count CRIT records injected"
    done
    rm -f /tmp/crit_records.json /tmp/crit_tmp.json
    echo "Done."

# Configure git to use project hooks
setup-hooks:
    git config core.hooksPath .githooks
    chmod +x .githooks/*

# Clean generated output files
clean:
    rm -rf {{outdir}}
