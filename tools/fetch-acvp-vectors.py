#!/usr/bin/env python3
"""Download the NIST ACVP ML-KEM (FIPS 203) test vectors and pack them into a
single gzipped JSON file used by the test suite.

Source: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files

Usage: python3 tools/fetch-acvp-vectors.py [output.json.gz]
"""
import gzip
import json
import os
import sys
import urllib.request

BASE = "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"
KEYGEN = f"{BASE}/ML-KEM-keyGen-FIPS203"
ENCAP = f"{BASE}/ML-KEM-encapDecap-FIPS203"


def fetch(url):
    with urllib.request.urlopen(url) as response:
        return json.load(response)


def by_tc(tests):
    return {test["tcId"]: test for test in tests}


def main():
    output = sys.argv[1] if len(sys.argv) > 1 else "src/test/resources/acvp/ml-kem-fips203.json.gz"

    keygen_prompt = fetch(f"{KEYGEN}/prompt.json")
    keygen_expected = fetch(f"{KEYGEN}/expectedResults.json")
    encap_prompt = fetch(f"{ENCAP}/prompt.json")
    encap_expected = fetch(f"{ENCAP}/expectedResults.json")

    result = {
        "source": "https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files",
        "algorithm": "ML-KEM",
        "revision": "FIPS203",
        "keyGen": [],
        "encapsulation": [],
        "decapsulation": [],
        "encapsulationKeyCheck": [],
        "decapsulationKeyCheck": [],
    }

    expected_by_tg = {group["tgId"]: by_tc(group["tests"]) for group in keygen_expected["testGroups"]}
    for group in keygen_prompt["testGroups"]:
        for test in group["tests"]:
            expected = expected_by_tg[group["tgId"]][test["tcId"]]
            result["keyGen"].append({
                "parameterSet": group["parameterSet"],
                "tcId": test["tcId"],
                "d": test["d"],
                "z": test["z"],
                "ek": expected["ek"],
                "dk": expected["dk"],
            })

    expected_by_tg = {group["tgId"]: by_tc(group["tests"]) for group in encap_expected["testGroups"]}
    for group in encap_prompt["testGroups"]:
        function = group["function"]
        if function == "encapsulation":
            bucket = "encapsulation"
        elif function == "decapsulation":
            bucket = "decapsulation"
        elif function == "encapsulationKeyCheck":
            bucket = "encapsulationKeyCheck"
        elif function == "decapsulationKeyCheck":
            bucket = "decapsulationKeyCheck"
        else:  # pragma: no cover - defensive
            raise SystemExit(f"unexpected function: {function}")
        for test in group["tests"]:
            expected = expected_by_tg[group["tgId"]][test["tcId"]]
            entry = {"parameterSet": group["parameterSet"], "tcId": test["tcId"]}
            if function == "encapsulation":
                entry.update(ek=test["ek"], m=test["m"], c=expected["c"], k=expected["k"])
            elif function == "decapsulation":
                entry.update(dk=test["dk"], c=test["c"], k=expected["k"])
            else:
                key = "ek" if function == "encapsulationKeyCheck" else "dk"
                entry.update({key: test[key], "valid": expected["testPassed"]})
            result[bucket].append(entry)

    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    with gzip.GzipFile(filename=output, mode="wb", mtime=0) as handle:
        handle.write(json.dumps(result, separators=(",", ":")).encode("utf-8"))

    counts = {k: len(v) for k, v in result.items() if isinstance(v, list)}
    print(f"wrote {output} ({os.path.getsize(output)} bytes): {counts}")


if __name__ == "__main__":
    main()
