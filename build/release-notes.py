#!/usr/bin/env python3
# Copyright (c) 2026 Default Gateway GmbH
# SPDX-License-Identifier: Apache-2.0
"""Write the release notes of a freshly built VyOS image with l2tvpp inside.

Called by build-iso.sh once the ISO exists, here and in the vpp-vlan-fast
repo (whose build bakes a second plugin into the same image and calls this
script with --vlanfast/--variant). Collects what went into the image from the
build tree (no ISO extraction): the vyos-build checkout, the live-build
squashfs that the ISO build leaves behind, the VPP debs, the l2tvpp (and
vpp-vlan-fast) checkouts and the hooks. Writes four files next to the ISO,
each named after the image so the file says which version it belongs to:

  <image>-release-notes.md  human-readable notes (the file people read on the mirror)
  <image>-release-notes.html  the same rendered for the browser (own Markdown subset renderer)
  <image>-release.json      the same facts, machine-readable (next build diffs against it)
  <image>.sha256            sha256 of the ISO, `sha256sum -c <image>.sha256` verifies a download

Usage (see build-iso.sh for the real call):
  release-notes.py --iso DIR/<image>.iso --l2tvpp L2TVPP_DIR --work WORK \
      [--vlanfast REPO --variant v2] [--tag fh] [--previous DIR] [--notes FILE] \
      [--l2tvpp-rev REV] [--vlanfast-rev REV] [--url BASEURL]

A second mode renders any Markdown file written in the same subset:
  release-notes.py --render IN.md OUT.html [--title TITLE]

Source revisions come from git when the checkout has a .git; a tree that was
rsync'ed without it needs --l2tvpp-rev / --vlanfast-rev (or the environment
variables L2TVPP_REV / VLANFAST_REV through build-iso.sh), otherwise the notes
say "unknown".
"""
import argparse
import datetime
import glob
import hashlib
import html as html_mod
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile


CSS = """
:root { color-scheme: light dark; --fg: #1b1f23; --bg: #ffffff; --muted: #57606a; --line: #d0d7de; --code: #f3f4f6; --link: #0a5bd3; }
@media (prefers-color-scheme: dark) { :root { --fg: #e6edf3; --bg: #0f1419; --muted: #9aa4af; --line: #30363d; --code: #1c2128; --link: #6cb6ff; } }
body { margin: 0 auto; padding: 24px 16px 48px; max-width: 62em; font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg); background: var(--bg); }
h1 { font-size: 1.6em; margin: 0 0 .6em; } h2 { font-size: 1.2em; margin: 1.6em 0 .5em; border-bottom: 1px solid var(--line); padding-bottom: .2em; }
code, pre { font: 0.92em ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; } code { background: var(--code); padding: .1em .3em; border-radius: 3px; overflow-wrap: anywhere; }
pre { background: var(--code); padding: 12px; border-radius: 6px; overflow-x: auto; } pre code { background: none; padding: 0; }
table { border-collapse: collapse; margin: 1em 0; width: 100%; } th, td { border: 1px solid var(--line); padding: 6px 10px; text-align: left; vertical-align: top; overflow-wrap: anywhere; } th:empty { display: none; } tr:has(> th:empty) { display: none; }
a { color: var(--link); } li { margin: .25em 0; } p.meta { color: var(--muted); font-size: .9em; }
"""


def md_inline(text):
    """Inline Markdown of the notes subset: code spans, bold, links."""
    out = []
    parts = re.split(r'(`[^`]*`)', text)
    for part in parts:
        if part.startswith('`') and part.endswith('`') and len(part) >= 2:
            out.append('<code>' + html_mod.escape(part[1:-1]) + '</code>')
            continue
        esc = html_mod.escape(part, quote=False)
        esc = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', esc)
        esc = re.sub(r'\[([^\]]+)\]\(([^)\s]+)\)', r'<a href="\2">\1</a>', esc)
        esc = re.sub(r'(?<![">])(https?://[^\s<]+[^\s<.,)])', r'<a href="\1">\1</a>', esc)
        out.append(esc)
    return ''.join(out)


def md_to_html(md, title=''):
    """Render the Markdown subset used by the release notes (headings, tables,
    bullet lists with indented continuation lines, fenced code, paragraphs)."""
    lines = md.splitlines()
    out, i, para = [], 0, []
    first_h1 = ''

    def flush():
        if para:
            out.append('<p>' + md_inline(' '.join(x.strip() for x in para)) + '</p>')
            para.clear()

    while i < len(lines):
        line = lines[i]
        if line.startswith('```'):
            flush()
            i += 1
            block = []
            while i < len(lines) and not lines[i].startswith('```'):
                block.append(lines[i])
                i += 1
            out.append('<pre><code>' + html_mod.escape('\n'.join(block)) + '</code></pre>')
            i += 1
            continue
        m = re.match(r'^(#{1,3})\s+(.*)$', line)
        if m:
            flush()
            level = len(m.group(1))
            if level == 1 and not first_h1:
                first_h1 = m.group(2)
            out.append(f'<h{level}>' + md_inline(m.group(2)) + f'</h{level}>')
            i += 1
            continue
        if line.startswith('|'):
            flush()
            rows = []
            while i < len(lines) and lines[i].startswith('|'):
                rows.append(lines[i])
                i += 1
            cells = [[c.strip() for c in r.strip().strip('|').split('|')] for r in rows]
            if len(cells) >= 2 and all(re.fullmatch(r':?-{2,}:?', c) for c in cells[1] if c):
                head, body = cells[0], cells[2:]
            else:
                head, body = None, cells
            t = ['<table>']
            if head:
                t.append('<tr>' + ''.join('<th>' + md_inline(c) + '</th>' for c in head) + '</tr>')
            for r in body:
                t.append('<tr>' + ''.join('<td>' + md_inline(c) + '</td>' for c in r) + '</tr>')
            t.append('</table>')
            out.append('\n'.join(t))
            continue
        if re.match(r'^[-*]\s+', line):
            flush()
            items = []
            while i < len(lines) and re.match(r'^[-*]\s+', lines[i]):
                item = re.sub(r'^[-*]\s+', '', lines[i])
                i += 1
                while i < len(lines) and re.match(r'^\s{2,}\S', lines[i]):
                    item += ' ' + lines[i].strip()
                    i += 1
                items.append(item)
            out.append('<ul>' + ''.join('<li>' + md_inline(x) + '</li>' for x in items) + '</ul>')
            continue
        if not line.strip():
            flush()
            i += 1
            continue
        para.append(line)
        i += 1
    flush()
    title = title or first_h1 or 'Release notes'
    return ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f'<title>{html_mod.escape(title)}</title>\n<style>{CSS}</style>\n</head>\n<body>\n'
            + '\n'.join(out) + '\n</body>\n</html>\n')


def sh(cmd, cwd=None):
    try:
        return subprocess.check_output(cmd, cwd=cwd, text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ''


def git_rev(path, override=''):
    """(short rev, branch, dirty) of a checkout; the override wins."""
    if override:
        return override, '', False
    if not os.path.isdir(os.path.join(path, '.git')) and not os.path.isfile(os.path.join(path, '.git')):
        return 'unknown', '', False
    rev = sh(['git', 'rev-parse', '--short', 'HEAD'], path) or 'unknown'
    branch = sh(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], path)
    dirty = bool(sh(['git', 'status', '--porcelain', '--untracked-files=no'], path))
    return rev, branch, dirty


def git_log(path, old, new, sub=None):
    if not old or not new or old == 'unknown' or new == 'unknown' or old == new:
        return []
    cmd = ['git', 'log', '--format=%h %s', f'{old}..{new}']
    if sub:
        cmd += ['--', sub]
    out = sh(cmd, path)
    return out.splitlines() if out else []


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def dpkg_versions(status_file, names):
    out = {}
    if not os.path.isfile(status_file):
        return out
    pkg = None
    with open(status_file, errors='replace') as f:
        for line in f:
            if line.startswith('Package: '):
                pkg = line[9:].strip()
            elif line.startswith('Version: ') and pkg:
                if pkg in names or (pkg.startswith('linux-image-') and pkg[12:13].isdigit()):
                    out[pkg] = line[9:].strip()
    return out


def added_pci_ids(vpp_py, hooks):
    """PCI IDs the DGW hooks added to VyOS's SUPPORTED_PCI_IDS: read the image's
    vpp.py when it could be extracted (comment tag 'DGW'), else the hook."""
    ids = []
    if os.path.isfile(vpp_py):
        with open(vpp_py, errors='replace') as f:
            for line in f:
                m = re.match(r"\s*'([0-9a-f]{4}:[0-9a-f]{4})',\s*#\s*(.*DGW.*)", line)
                if m:
                    ids.append((m.group(1), m.group(2).strip()))
        if ids:
            return ids
    for h in hooks:
        with open(h, errors='replace') as f:
            for line in f:
                m = re.match(r'\s*add_(?:after|before)\s+([0-9a-f]{4}:[0-9a-f]{4})\s+"([^"]*)"', line)
                if m:
                    ids.append((m.group(1), m.group(2).strip()))
    return ids


def l2tvpp_features(src):
    """CLI features of the l2tvpp plugin, from its sources (branch-dependent)."""
    feats = []
    files = glob.glob(os.path.join(src, 'plugin', 'l2tvpp', '*.c'))
    text = ''
    for f in files:
        with open(f, errors='replace') as fh:
            text += fh.read()
    for name in ('flow-handoff', 'encap-fastpath', 'inner-checksum', 'spray'):
        if name in text:
            feats.append(name)
    if 'handoff' in text:
        feats.insert(0, 'worker handoff')
    return feats


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--render':
        rp = argparse.ArgumentParser()
        rp.add_argument('--render', nargs=2, metavar=('IN.md', 'OUT.html'), required=True)
        rp.add_argument('--title', default='')
        r = rp.parse_args()
        with open(r.render[1], 'w') as f:
            f.write(md_to_html(open(r.render[0]).read(), r.title))
        print(f'rendered {r.render[1]}')
        return 0
    ap = argparse.ArgumentParser()
    ap.add_argument('--iso', required=True)
    ap.add_argument('--l2tvpp', required=True, help='l2tvpp checkout')
    ap.add_argument('--work', required=True, help='build/work (holds vyos-build)')
    ap.add_argument('--vlanfast', default='', help='vpp-vlan-fast checkout when that plugin is in the image')
    ap.add_argument('--variant', default='', help='vlan-fast plugin variant (with --vlanfast)')
    ap.add_argument('--tag', default='')
    ap.add_argument('--previous', default='', help='folder of the previous image (<image>-release.json)')
    ap.add_argument('--notes', default='', help='file with free-text notes for this build')
    ap.add_argument('--l2tvpp-rev', default='')
    ap.add_argument('--vlanfast-rev', default='')
    ap.add_argument('--url', default='', help='public base URL of the download host')
    a = ap.parse_args()
    if bool(a.vlanfast) != bool(a.variant):
        ap.error('--vlanfast and --variant go together')

    iso = os.path.abspath(a.iso)
    outdir = os.path.dirname(iso)
    name = os.path.basename(iso)
    version = re.sub(r'^vyos-', '', re.sub(r'-generic-amd64\.iso$', '', name))
    vb = os.path.join(a.work, 'vyos-build')
    pkgdir = os.path.join(vb, 'scripts', 'package-build', 'vpp')

    # --- VyOS side: read version.json, the dpkg status and the vpp conf_mode
    # script out of the squashfs that live-build leaves in build/binary/live/
    # (the chroot directory is reset to the base system at the end of the
    # build and does not reflect the image). Falls back to the small files
    # live-build keeps next to it.
    bdir = os.path.join(vb, 'build', 'binary')
    squash = os.path.join(bdir, 'live', 'filesystem.squashfs')
    tmp = tempfile.mkdtemp(prefix='release-notes.')
    vjson = os.path.join(bdir, 'version.json')
    status = ''
    vpp_py = ''
    if os.path.isfile(squash) and shutil.which('unsquashfs'):
        subprocess.run(['unsquashfs', '-q', '-n', '-d', os.path.join(tmp, 'x'), squash,
                        'usr/share/vyos/version.json', 'var/lib/dpkg/status',
                        'usr/libexec/vyos/conf_mode/vpp.py'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.path.isfile(os.path.join(tmp, 'x', 'usr', 'share', 'vyos', 'version.json')):
            vjson = os.path.join(tmp, 'x', 'usr', 'share', 'vyos', 'version.json')
        status = os.path.join(tmp, 'x', 'var', 'lib', 'dpkg', 'status')
        vpp_py = os.path.join(tmp, 'x', 'usr', 'libexec', 'vyos', 'conf_mode', 'vpp.py')
    vinfo = {}
    if os.path.isfile(vjson):
        try:
            vinfo = json.load(open(vjson))
        except ValueError:
            vinfo = {}
    built_on = vinfo.get('built_on') or datetime.datetime.fromtimestamp(
        os.path.getmtime(iso), datetime.timezone.utc).strftime('%a %d %b %Y %H:%M UTC')
    vb_branch = vinfo.get('build_branch') or sh(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], vb)
    vb_commit = (vinfo.get('build_git') or sh(['git', 'rev-parse', 'HEAD'], vb))[:8]
    names = {'vpp', 'vyos-1x', 'vyos-intel-ice', 'frr', 'accel-ppp', 'vyos-linux-firmware'}
    pkgs = dpkg_versions(status, names) if status else {}
    if not pkgs and os.path.isfile(os.path.join(bdir, 'live', 'filesystem.packages')):
        # "name  version" per line
        for line in open(os.path.join(bdir, 'live', 'filesystem.packages'), errors='replace'):
            parts = line.split()
            if len(parts) >= 2 and (parts[0] in names or (parts[0].startswith('linux-image-') and parts[0][12:13].isdigit())):
                pkgs[parts[0]] = parts[1]
    kernel = next((k[12:] for k in pkgs if k.startswith('linux-image-')), '')
    debs = sorted(glob.glob(os.path.join(a.vlanfast or a.l2tvpp, 'build', 'out', 'vpp_*.deb')))
    vpp_ver = pkgs.get('vpp') or (re.sub(r'^vpp_(.*)_amd64\.deb$', r'\1', os.path.basename(debs[-1])) if debs else 'unknown')
    patches_rev = sh(['git', 'rev-parse', '--short', 'HEAD'], os.path.join(pkgdir, 'vyos-vpp-patches'))
    patches_date = sh(['git', 'log', '-1', '--format=%cs'], os.path.join(pkgdir, 'vyos-vpp-patches'))

    # --- our side
    l2_rev, l2_branch, l2_dirty = git_rev(a.l2tvpp, a.l2tvpp_rev)
    vf_rev, vf_branch, vf_dirty = git_rev(a.vlanfast, a.vlanfast_rev) if a.vlanfast else ('', '', False)
    hooks_vf = sorted(glob.glob(os.path.join(a.vlanfast, 'build', 'vyos-hooks', '*.chroot'))) if a.vlanfast else []
    hooks_l2 = sorted(glob.glob(os.path.join(a.l2tvpp, 'build', 'vyos-hooks', '*.chroot')))
    pci = added_pci_ids(vpp_py, hooks_vf)
    shutil.rmtree(tmp, ignore_errors=True)
    feats = l2tvpp_features(a.l2tvpp)

    size = os.path.getsize(iso)
    digest = sha256(iso)

    # --- previous image for the change list
    prev = {}
    prev_json = glob.glob(os.path.join(a.previous, '*-release.json')) if a.previous else []
    if prev_json:
        try:
            prev = json.load(open(prev_json[0]))
        except ValueError:
            prev = {}
    prev_name = prev.get('image', '')
    l2_changes = git_log(a.l2tvpp, prev.get('l2tvpp', {}).get('rev'), l2_rev) if not a.l2tvpp_rev else []
    vf_changes = git_log(a.vlanfast, prev.get('vlan_fast', {}).get('rev'), vf_rev) if a.vlanfast and not a.vlanfast_rev else []

    notes = ''
    if a.notes and os.path.isfile(a.notes):
        notes = open(a.notes).read().strip()
    elif os.environ.get('RELEASE_NOTES'):
        notes = os.environ['RELEASE_NOTES'].strip()

    folder = re.sub(r'-generic-amd64\.iso$', '', name)
    base = a.url.rstrip('/') + '/' + folder + '/' if a.url else '<download-url>/' + folder + '/'

    facts = {
        'image': folder, 'iso': name, 'size': size, 'sha256': digest, 'built_on': built_on,
        'vyos': {'branch': vb_branch, 'vyos_build': vb_commit, 'vyos_1x': pkgs.get('vyos-1x', ''),
                 'kernel': kernel, 'ice': pkgs.get('vyos-intel-ice', ''), 'frr': pkgs.get('frr', ''),
                 'accel_ppp': pkgs.get('accel-ppp', '')},
        'vpp': {'version': vpp_ver, 'vyos_vpp_patches': patches_rev, 'vyos_vpp_patches_date': patches_date},
        'l2tvpp': {'rev': l2_rev, 'branch': l2_branch, 'dirty': l2_dirty, 'features': feats},
        'vlan_fast': ({'rev': vf_rev, 'branch': vf_branch, 'dirty': vf_dirty, 'variant': a.variant, 'tag': a.tag}
                      if a.vlanfast else {'included': False, 'tag': a.tag}),
        'supported_nic_additions': [p[0] for p in pci],
        'hooks': [os.path.basename(h) for h in hooks_l2 + hooks_vf],
        'previous': prev_name, 'notes': notes,
        'generated': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    }
    with open(os.path.join(outdir, folder + '-release.json'), 'w') as f:
        json.dump(facts, f, indent=2)
        f.write('\n')
    with open(os.path.join(outdir, folder + '.sha256'), 'w') as f:
        f.write(f'{digest}  {name}\n')

    def rev(r, b, d):
        s = f'`{r}`'
        if b and b not in ('HEAD', 'main', 'master'):
            s = f'`{b}` @ ' + s
        if d:
            s += ' (uncommitted changes in the tree)'
        return s

    md = []
    md.append(f'# VyOS image {folder}\n')
    plugins = 'the l2tvpp and vlan-fast plugins' if a.vlanfast else 'the l2tvpp plugin'
    md.append(f'Built {built_on} on the DGW build host from VyOS `{vb_branch}` '
              f'(vyos-build `{vb_commit}`) with {plugins} inside VPP.\n')
    md.append('| | |')
    md.append('|---|---|')
    md.append(f'| ISO | `{name}` ({size / 1e6:.0f} MB) |')
    md.append(f'| SHA256 | `{digest}` |')
    vy = f'`{vb_branch}`, vyos-build `{vb_commit}`'
    if pkgs.get('vyos-1x'):
        vy += f', vyos-1x `{pkgs["vyos-1x"]}`'
    if kernel:
        vy += f', kernel `{kernel}`'
    md.append(f'| VyOS | {vy} |')
    vp = f'`{vpp_ver}` (FDio `stable/2510`'
    if patches_rev:
        vp += f' + vyos-vpp-patches `{patches_rev}` of {patches_date}'
    vp += ')'
    md.append(f'| VPP | {vp} |')
    md.append(f'| l2tvpp | {rev(l2_rev, l2_branch, l2_dirty)} |')
    md.append(f'| vlan-fast | variant `{a.variant}`, {rev(vf_rev, vf_branch, vf_dirty)} |' if a.vlanfast
              else '| vlan-fast | not included |')
    if pkgs.get('vyos-intel-ice'):
        md.append(f'| ice driver | `{pkgs["vyos-intel-ice"]}` (vyos-intel-ice, DDP package included) |')
    md.append('')
    md.append('## What is inside\n')
    f1 = f'- **l2tvpp**: L2TPv2 LNS data plane plugin and the `l2tvppd` sync daemon'
    if feats:
        f1 += ' (CLI features: ' + ', '.join(feats) + ')'
    md.append(f1 + '.')
    if a.vlanfast:
        md.append(f'- **delta_vlan_fast** variant `{a.variant}`: AVX2 802.1Q parser, boot helper '
                  f'`/usr/libexec/vlan-fast/vlan-fast.py`, ABI manifest `/usr/share/vlan-fast/manifest.json`.')
    if pci:
        md.append('- **Supported VPP NICs** added to VyOS\'s list (no `set vpp settings allow-unsupported-nics` needed): '
                  + ', '.join(f'`{i}` {c.replace(", DGW", "").replace(" (DGW)", "")}' for i, c in pci) + '.')
    else:
        md.append('- No additions to VyOS\'s supported VPP NIC list in this image.')
    md.append('- Image hooks: ' + ', '.join(f'`{h}`' for h in facts['hooks']) + '.')
    md.append('')
    if prev_name:
        md.append(f'## Changes since {prev_name}\n')
        if l2_changes:
            md.append('l2tvpp:\n')
            md += [f'- {c}' for c in l2_changes]
            md.append('')
        if vf_changes:
            md.append('vpp-vlan-fast:\n')
            md += [f'- {c}' for c in vf_changes]
            md.append('')
        if not l2_changes and not vf_changes:
            md.append('- No source changes recorded between the two builds (same revisions, or revisions '
                      'not known to git); see the Notes.\n')
    md.append('## Notes\n')
    md.append(notes if notes else 'No notes were given for this build (RELEASE_NOTES_FILE / RELEASE_NOTES).')
    md.append('')
    md.append('## Status\n')
    md.append('Untested at publication. Update this file (and the copy in `releases/` of the '
              'vpp-vlan-fast repo) once the image has run on hardware.\n')
    md.append('## Install\n')
    md.append('```')
    md.append(f'add system image {base}{name}')
    md.append('```')
    md.append('')
    md.append(f'Verify a download with `sha256sum -c {folder}.sha256` in the folder `{base}`.')
    md.append('')
    with open(os.path.join(outdir, folder + '-release-notes.md'), 'w') as f:
        f.write('\n'.join(md))
    with open(os.path.join(outdir, folder + '-release-notes.html'), 'w') as f:
        f.write(md_to_html('\n'.join(md), 'VyOS image ' + folder))
    # one line for the index on the download host
    with open(os.path.join(outdir, folder + '-index-line.md'), 'w') as f:
        head = notes.splitlines()[0] if notes else (
            f'l2tvpp {l2_rev}, vlan-fast {a.variant} {vf_rev}' if a.vlanfast else f'l2tvpp {l2_rev}, single-plugin image')
        f.write(f'- [{folder}]({folder}/) built {built_on}, VPP `{vpp_ver}`: {head}\n')
    print(f'release notes written to {outdir}/{folder}-release-notes.md (+ .html)')


if __name__ == '__main__':
    sys.exit(main())
