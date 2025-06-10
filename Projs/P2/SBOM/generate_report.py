#!/usr/bin/env python3
import json
import sys

def parse_sbom_json(json_path, output_path):
    # Carrega o JSON do SBOM
    with open(json_path, 'r', encoding='utf-8') as f:
        bom = json.load(f)

    # 1) Componentes
    comps = []
    for comp in bom.get('components', []):
        name    = comp.get('name', 'N/A')
        version = comp.get('version', 'N/A')
        purl    = comp.get('purl', comp.get('bom-ref', 'N/A'))
        comps.append((name, version, purl))

    # 2) Dependências
    deps = {}   # { ref : [ref1, ref2, ...], ... }
    for d in bom.get('dependencies', []):
        parent = d.get('ref')
        # dependsOn pode ser lista de strings ou de dicts
        raw = d.get('dependsOn', [])
        children = []
        for item in raw:
            if isinstance(item, dict):
                children.append(item.get('ref'))
            elif isinstance(item, str):
                children.append(item)
        deps[parent] = children

    # 3) Licenças
    lic = {}    # { purl : [lic1, lic2], ... }
    for comp in bom.get('components', []):
        purl = comp.get('purl', comp.get('bom-ref'))
        ls = []
        for licinfo in comp.get('licenses', []):
            if 'license' in licinfo and isinstance(licinfo['license'], dict) and 'id' in licinfo['license']:
                ls.append(licinfo['license']['id'])
            elif 'expression' in licinfo:
                ls.append(licinfo['expression'])
        lic[purl] = ls or ['N/A']

    # 4) Vulnerabilidades
    vulns = []  # [(id,severity,score), ...]
    for v in bom.get('vulnerabilities', []):
        vid = v.get('id') or v.get('ref')
        # ratings pode ser lista de dicts
        ratings = v.get('ratings', [])
        if ratings and isinstance(ratings, list):
            first = ratings[0]
            sev   = first.get('severity', 'N/A')
            score = first.get('score', 'N/A')
        else:
            sev = score = 'N/A'
        vulns.append((vid, sev, score))

    # Escrever relatório
    with open(output_path, 'w', encoding='utf-8') as out:
        out.write("## Componentes Instalados\n")
        for name, version, purl in comps:
            out.write(f"- {name}=={version} ({purl})\n")

        out.write("\n## Dependências\n")
        for parent, children in deps.items():
            out.write(f"- {parent}:\n")
            for c in children:
                out.write(f"    - {c}\n")

        out.write("\n## Licenças\n")
        for purl, ls in lic.items():
            out.write(f"- {purl}:\n")
            for l in ls:
                out.write(f"    - {l}\n")

        out.write("\n## Vulnerabilidades\n")
        if vulns:
            for vid, sev, sc in vulns:
                out.write(f"- {vid}: Severity={sev}, Score={sc}\n")
        else:
            out.write("Nenhuma vulnerabilidade reportada.\n")

if __name__ == "__main__":
    # Permite passar SBOM JSON e arquivo de saída como argumentos
    js = sys.argv[1] if len(sys.argv) >= 2 else "sbom.json"
    out = sys.argv[2] if len(sys.argv) >= 3 else "report.txt"
    parse_sbom_json(js, out)
    print(f"Relatório gerado em '{out}'")
