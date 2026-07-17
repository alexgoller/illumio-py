# -*- coding: utf-8 -*-

"""Spec-conformance audit for illumio-py.

Mechanically diffs every ``@pce_api``-registered dataclass model against its
authoritative JSON schema from the Illumio webservices bundle, and reports:

- ``missing_field``   - a schema property with no corresponding model field
- ``extra_field``     - a non-base model field absent from the schema
- ``no_schema``       - a registration whose schema could not be resolved
- ``duplicate_reg``   - an API name registered more than once in the source
- ``uncovered_class`` - an API-index class with no library registration

This is read-only. It writes a markdown + JSON report and exits 0. It does not
modify library code.

Usage:
    python tools/spec_audit.py [--bundle DIR] [--out FILE]
"""
import argparse
import json
import os
import re
import sys
from dataclasses import fields
from glob import glob

# Ensure the working-tree package is imported (not a stale site-packages copy).
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import illumio  # noqa: F401  (registers all @pce_api models)
from illumio.util.constants import PCE_APIS

DEFAULT_BUNDLE = os.path.join(REPO_ROOT, 'webservices-v2-experimental-26.3.0')

# Fields provided by the base classes (Reference / IllumioObject / MutableObject).
# Present on nearly every schema; excluded from "extra_field" noise.
BASE_FIELDS = {
    'href', 'name', 'description', 'external_data_set', 'external_data_reference',
    'caps', 'created_at', 'updated_at', 'deleted_at', 'created_by', 'updated_by',
    'deleted_by', 'update_type', 'delete_type',
}

# Library API name -> (class name in illumio.api.json) OR ('schema', schema_basename).
# For registrations whose name does not directly match an index class.
ALIASES = {
    'rules': 'sec_rules',
    'org_settings': 'settings',
    'event_settings': ('schema', 'settings_events_get'),
    'report_settings': ('schema', 'settings_reports_get'),
    'permissions': ('schema', 'orgs_permissions_get'),
    'auth_security_principals': ('schema', 'orgs_auth_security_principals_get'),
    'roles': ('schema', 'orgs_roles_get'),
    'access_restrictions': ('schema', 'orgs_access_restrictions_get'),
    # Deny rules: the richer deny_rules_get schema (not wired to a path in this
    # experimental index, but live-validated as the real object).
    'deny_rules': ('schema', 'deny_rules_get'),
    'override_deny_rules': ('schema', 'deny_rules_get'),
}


def build_schema_index(bundle):
    """basename (without .schema.json) -> absolute file path."""
    index = {}
    for path in glob(os.path.join(bundle, '**', '*.schema.json'), recursive=True):
        base = os.path.basename(path)[:-len('.schema.json')]
        index.setdefault(base, path)
    return index


def resolve_props(schema_path, schema_index, _seen=None):
    """Recursively collect all object property names reachable from a schema."""
    if _seen is None:
        _seen = set()
    if not schema_path or schema_path in _seen:
        return set()
    _seen.add(schema_path)
    try:
        with open(schema_path) as f:
            schema = json.load(f)
    except (OSError, ValueError):
        return set()
    return _resolve_node(schema, schema, os.path.dirname(schema_path), schema_index, _seen)


def _pointer(root, ref):
    """Resolve an internal JSON pointer like '#/definitions/user_full'."""
    node = root
    for part in ref.lstrip('#/').split('/'):
        if not part:
            continue
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return node


def _resolve_node(node, root, base_dir, schema_index, seen):
    props = set()
    if not isinstance(node, dict):
        return props
    if '$ref' in node:
        ref = node['$ref']
        if ref.startswith('#'):
            target = _pointer(root, ref)
            key = base_dir + '::' + ref
            if target is not None and key not in seen:
                seen.add(key)
                props |= _resolve_node(target, root, base_dir, schema_index, seen)
        else:
            ref_path = os.path.normpath(os.path.join(base_dir, ref))
            if not os.path.exists(ref_path):
                ref_path = schema_index.get(os.path.basename(ref)[:-len('.schema.json')])
            if ref_path:
                props |= resolve_props(ref_path, schema_index, seen)
    if 'properties' in node:
        props |= set(node['properties'].keys())
    for combiner in ('allOf', 'anyOf', 'oneOf'):
        for sub in node.get(combiner, []):
            props |= _resolve_node(sub, root, base_dir, schema_index, seen)
    if node.get('type') == 'array' and isinstance(node.get('items'), dict):
        props |= _resolve_node(node['items'], root, base_dir, schema_index, seen)
    return props


def schema_for_registration(name, classes, schema_index):
    """Return (schema_basename, schema_path) for a library API name, or (None, None)."""
    target = ALIASES.get(name, name)
    if isinstance(target, tuple) and target[0] == 'schema':
        base = target[1]
        return base, schema_index.get(base)
    cls = classes.get(target)
    if not cls:
        return None, None
    methods = cls.get('methods', {})
    # Prefer the instance/collection GET schema (the representation of the object).
    for m in ('get_instance', 'get_collection', 'get'):
        schema = methods.get(m, {}).get('schema')
        if schema:
            return schema, schema_index.get(schema)
    return None, None


def source_duplicate_registrations():
    """Scan source for @pce_api('name', ...) occurrences; return name -> count>1."""
    counts = {}
    # Match only real decorators (column 0), not @pce_api examples inside docstrings
    # (e.g. the decorator's own docstring uses ">>> @pce_api('labels', ...)").
    pattern = re.compile(r"^@pce_api\(\s*'([^']+)'", re.MULTILINE)
    for path in glob(os.path.join(REPO_ROOT, 'illumio', '**', '*.py'), recursive=True):
        with open(path) as f:
            for m in pattern.finditer(f.read()):
                counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    return {n: c for n, c in counts.items() if c > 1}


def audit(bundle):
    api = json.load(open(os.path.join(bundle, 'v2', 'illumio.api.json')))
    classes = api['classes']
    schema_index = build_schema_index(bundle)

    findings = []
    covered_classes = set()

    for name in sorted(PCE_APIS):
        reg = PCE_APIS[name]
        model_fields = {f.name for f in fields(reg.object_class)}
        schema_base, schema_path = schema_for_registration(name, classes, schema_index)
        target = ALIASES.get(name, name)
        if isinstance(target, str):
            covered_classes.add(target)

        if not schema_path:
            findings.append({
                'type': 'no_schema', 'api': name,
                'model': reg.object_class.__name__,
                'detail': 'no schema resolved (schema_base=%s)' % schema_base,
            })
            continue

        schema_props = resolve_props(schema_path, schema_index)
        if not schema_props:
            findings.append({
                'type': 'no_schema', 'api': name, 'model': reg.object_class.__name__,
                'detail': 'schema %s resolved to zero properties' % schema_base,
            })
            continue

        missing = sorted(schema_props - model_fields)
        extra = sorted((model_fields - schema_props) - BASE_FIELDS)
        if missing:
            findings.append({
                'type': 'missing_field', 'api': name, 'model': reg.object_class.__name__,
                'schema': schema_base, 'fields': missing,
            })
        if extra:
            findings.append({
                'type': 'extra_field', 'api': name, 'model': reg.object_class.__name__,
                'schema': schema_base, 'fields': extra,
            })

    for name, count in sorted(source_duplicate_registrations().items()):
        findings.append({'type': 'duplicate_reg', 'api': name, 'count': count})

    # Collection classes in the index with no library registration (coverage gaps).
    collection_classes = sorted(
        n for n, c in classes.items()
        if c.get('collection') and n not in covered_classes and n not in PCE_APIS
    )
    for n in collection_classes:
        findings.append({'type': 'uncovered_class', 'api': n})

    return findings


def render_markdown(findings):
    by_type = {}
    for f in findings:
        by_type.setdefault(f['type'], []).append(f)

    out = ['# illumio-py spec-conformance audit report', '']
    out.append('Generated by `tools/spec_audit.py` against the webservices bundle. Read-only.')
    out.append('')
    out.append('### How to read this')
    out.append('')
    out.append('- **missing_field** is high-confidence: the authoritative schema has a '
               'property the model lacks. These are additive, backwards-compatible fixes.')
    out.append('- **extra_field** needs per-item verification: it may be a legitimate field '
               'rename in the schema (the model uses an older name — check the same model\'s '
               'missing_field list), an intentional convenience deviation, or a genuine stale '
               'field to deprecate.')
    out.append('- **uncovered_class** counts only `@pce_api` registrations. Many listed here '
               'are in fact implemented as custom `PolicyComputeEngine` methods '
               '(e.g. workload_interfaces, ven_software_releases, api_keys, traffic_flows) and '
               'are NOT true gaps. Genuine gaps are the ones with no method either.')
    out.append('- **no_schema** with `schema_base=None` means no schema exists in the bundle '
               'for that resource (not a model defect).')
    out.append('- Base fields (href/name/description/timestamps/caps/external_data_*) are '
               'excluded from extra_field noise.')
    out.append('')
    order = ['duplicate_reg', 'no_schema', 'missing_field', 'extra_field', 'uncovered_class']
    titles = {
        'duplicate_reg': 'Duplicate registrations (same API name registered twice)',
        'no_schema': 'Registrations with no resolvable schema (endpoint/naming to verify)',
        'missing_field': 'Missing fields (schema property absent from model — additive fix)',
        'extra_field': 'Extra model fields (not in schema — verify: deprecated / wrong / experimental)',
        'uncovered_class': 'Index collection classes with no library registration (coverage gap — report only)',
    }
    out.append('## Summary')
    for t in order:
        out.append('- **%s**: %d' % (titles[t], len(by_type.get(t, []))))
    out.append('')

    for t in order:
        items = by_type.get(t, [])
        if not items:
            continue
        out.append('## %s' % titles[t])
        out.append('')
        if t == 'duplicate_reg':
            for f in items:
                out.append('- `%s` registered %d times' % (f['api'], f['count']))
        elif t == 'no_schema':
            for f in items:
                out.append('- `%s` (%s) — %s' % (f['api'], f['model'], f['detail']))
        elif t in ('missing_field', 'extra_field'):
            for f in sorted(items, key=lambda x: -len(x['fields'])):
                out.append('- `%s` (`%s`, schema `%s`): %s'
                           % (f['api'], f['model'], f['schema'], ', '.join('`%s`' % x for x in f['fields'])))
        else:
            out.append(', '.join('`%s`' % f['api'] for f in items))
        out.append('')
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bundle', default=DEFAULT_BUNDLE)
    ap.add_argument('--out', default=os.path.join(REPO_ROOT, 'tasks', 'spec-audit-report.md'))
    args = ap.parse_args()

    findings = audit(args.bundle)
    md = render_markdown(findings)
    with open(args.out, 'w') as f:
        f.write(md + '\n')
    with open(args.out.replace('.md', '.json'), 'w') as f:
        json.dump(findings, f, indent=2)

    counts = {}
    for x in findings:
        counts[x['type']] = counts.get(x['type'], 0) + 1
    print('Audit complete. Findings by type:', counts)
    print('Report:', args.out)


if __name__ == '__main__':
    main()
