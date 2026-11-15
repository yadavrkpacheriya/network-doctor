import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:permission_handler/permission_handler.dart';

import '../clean/scanner.dart';

/// Phone clean-up: finds duplicate files, junk (temp/log/leftover installers/empty) and the biggest files in the
/// shared storage you grant, and lets you delete them. It also clears this app's own cache. It canNOT clear other
/// apps' caches or the system cache - Android does not allow that without root; the button at the bottom opens the
/// phone's own Storage settings for that.
class CleanScreen extends StatefulWidget {
  const CleanScreen({super.key});
  @override
  State<CleanScreen> createState() => _CleanScreenState();
}

const _kindColor = {
  CleanKind.duplicate: Color(0xFFA78BFA),
  CleanKind.junk: Color(0xFFF59E0B),
  CleanKind.installer: Color(0xFFFB7185),
  CleanKind.emptyFolder: Color(0xFF9CA3AF),
  CleanKind.big: Color(0xFF38BDF8),
};

class _Group {
  _Group(this.kind, this.items);
  final CleanKind kind;
  final List<CleanItem> items;
  Color get color => _kindColor[kind]!;
}

class _CleanScreenState extends State<CleanScreen> {
  bool _busy = false;
  String _status = '';
  int _scanned = 0;
  final _sel = <String>{}; // selected paths to delete
  List<_Group> _groups = [];
  int _protected = 0; // files left alone (other apps' private folders)

  // Scan the WHOLE internal storage, not just a few folders, so it cleans the full phone (Downloads, WhatsApp,
  // Telegram, screenshots, camera, everything). Only Android/data and Android/obb are skipped - those are other
  // apps' PRIVATE files/caches, which Android does not let any app (without root) read or delete.
  static const _scanRoot = '/storage/emulated/0';
  static const _skip = ['/Android/data', '/Android/obb', '/.Trash', '/LOST.DIR'];
  final List<String> _emptyDirs = [];

  void _set(void Function() fn) {
    if (mounted) setState(fn);
  }

  Future<bool> _ensurePermission() async {
    if (await Permission.manageExternalStorage.isGranted) return true;
    final r = await Permission.manageExternalStorage.request();
    if (r.isGranted) return true;
    // older phones (Android 10 and below) use the plain storage permission
    final s = await Permission.storage.request();
    return s.isGranted;
  }

  Future<void> _scan() async {
    _set(() {
      _busy = true;
      _status = 'Asking for file access...';
      _groups = [];
      _sel.clear();
      _scanned = 0;
      _protected = 0;
    });
    if (!await _ensurePermission()) {
      _set(() {
        _busy = false;
        _status = 'Without "All files access" I cannot scan your storage. Tap Scan again and allow it, or open '
            'Settings and grant it.';
      });
      return;
    }
    final all = <FileMeta>[];
    _emptyDirs.clear();
    _set(() => _status = 'Scanning the whole phone...');
    await _walk(Directory(_scanRoot), all, 0);
    _set(() => _status = 'Looking for duplicates in ${all.length} files...');
    await _hashCandidates(all);
    final plan = buildCleanPlan(all, _emptyDirs);
    final groups = [for (final e in plan.items.entries) _Group(e.key, e.value)];
    final sel = <String>{};
    for (final g in groups) {
      if (g.kind.preselect) sel.addAll(g.items.map((i) => i.file.path));
    }
    _set(() {
      _groups = groups;
      _protected = plan.protectedCount;
      _sel
        ..clear()
        ..addAll(sel);
      _busy = false;
      _status = groups.isEmpty
          ? 'Nothing to clean - your storage looks tidy. $_scanned files checked.'
          : 'Found ${humanSize(plan.totalBytes)} in ${plan.totalCount} files (of $_scanned checked). '
              'Tick what you want gone - nothing is deleted until you confirm.';
    });
  }

  // Walk one folder, collecting files and noting empty folders, skipping other apps' private trees and symlinks.
  // Manual recursion (not list(recursive:true)) so we can PRUNE Android/data etc. and spot empty folders. Capped
  // so a huge tree can't run away.
  Future<bool> _walk(Directory dir, List<FileMeta> all, int depth) async {
    if (depth > 12 || _scanned > 300000) return false;
    final p = dir.path;
    for (final s in _skip) {
      if (p.endsWith(s) || p.contains('$s/')) return false; // a pruned, skipped tree - not "empty"
    }
    var hasChild = false;
    try {
      await for (final e in dir.list(followLinks: false)) {
        hasChild = true;
        if (e is File) {
          try {
            final st = await e.stat();
            all.add(FileMeta(e.path, st.size, st.modified.millisecondsSinceEpoch));
            _scanned++;
            if (_scanned % 500 == 0) _set(() => _status = 'Scanning the whole phone... $_scanned files');
          } catch (_) {/* unreadable file */}
        } else if (e is Directory) {
          await _walk(e, all, depth + 1);
        }
      }
    } catch (_) {
      return true; // unreadable folder - leave it, don't call it empty
    }
    if (!hasChild && depth > 0) _emptyDirs.add(p);
    return true;
  }

  // Hash only files that share a size (cheap), and only a slice of each (first + last 256 KB + size) so even big
  // media hash fast while still being safe to call an exact duplicate.
  Future<void> _hashCandidates(List<FileMeta> all) async {
    final need = sizesNeedingHash(all, minSize: 1024).toSet();
    var done = 0;
    for (final f in all) {
      if (!need.contains(f.size)) continue;
      try {
        f.hash = await _sliceHash(f.path, f.size);
      } catch (_) {/* unreadable - leave hash null so it is ignored */}
      if (++done % 100 == 0) _set(() => _status = 'Comparing files... $done');
    }
  }

  Future<String> _sliceHash(String path, int size) async {
    final raf = await File(path).open();
    try {
      const slice = 256 * 1024;
      final head = await raf.read(slice);
      List<int> tail = const [];
      if (size > slice * 2) {
        await raf.setPosition(size - slice);
        tail = await raf.read(slice);
      }
      return sha1.convert([...head, ...tail, size & 0xFF, (size >> 8) & 0xFF, (size >> 16) & 0xFF]).toString();
    } finally {
      await raf.close();
    }
  }

  Iterable<CleanItem> get _selItems sync* {
    for (final g in _groups) {
      for (final i in g.items) {
        if (_sel.contains(i.file.path)) yield i;
      }
    }
  }

  int get _selBytes => _selItems.fold(0, (n, i) => n + i.file.size);

  Future<void> _deleteSelected() async {
    final chosen = _selItems.toList();
    if (chosen.isEmpty) return;
    final safe = safeToDelete(chosen);
    final ok = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: Text('Delete ${safe.toDelete.length} file${safe.toDelete.length == 1 ? '' : 's'} permanently?'),
        content: SingleChildScrollView(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
            const Text('What will be deleted:', style: TextStyle(fontWeight: FontWeight.w700)),
            const SizedBox(height: 6),
            for (final k in CleanKind.values)
              if (safe.toDelete.any((i) => i.kind == k))
                Padding(
                  padding: const EdgeInsets.only(bottom: 4),
                  child: Text(
                    '${k.tag}: ${safe.toDelete.where((i) => i.kind == k).length} · '
                    '${humanSize(totalBytes(safe.toDelete.where((i) => i.kind == k).map((i) => i.file)))}',
                    style: TextStyle(color: _kindColor[k], fontWeight: FontWeight.w600),
                  ),
                ),
            const SizedBox(height: 8),
            Text('Frees ${humanSize(totalBytes(safe.toDelete.map((i) => i.file)))}.'),
            if (safe.toDelete.any((i) => i.kind == CleanKind.duplicate))
              const Text('Duplicates: one original of each is kept.'),
            if (safe.toDelete.any((i) => i.kind == CleanKind.big))
              const Text('BIG FILES are your own files, not junk - make sure you do not need them.'),
            if (safe.heldBack.isNotEmpty)
              Text('${safe.heldBack.length} duplicate(s) kept because their original is also ticked.'),
            const SizedBox(height: 10),
            const Text(
              'PERMANENT: there is no trash or recycle bin. These files cannot be recovered.',
              style: TextStyle(color: Color(0xFFEF4444), fontWeight: FontWeight.w700),
            ),
          ]),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: const Color(0xFFDC2626), foregroundColor: Colors.white),
            onPressed: () => Navigator.pop(c, true),
            child: const Text('Delete permanently'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    _set(() {
      _busy = true;
      _status = 'Deleting...';
    });
    var freed = 0, fail = 0, kept = 0;
    final gone = <String>{};
    for (final i in safe.toDelete) {
      try {
        // last safety check: a duplicate is only removed while its kept original still exists
        if (i.kind == CleanKind.duplicate && !await File(i.keepPath!).exists()) {
          kept++;
          continue;
        }
        if (i.kind == CleanKind.emptyFolder) {
          await Directory(i.file.path).delete(); // non-recursive: fails (safely) if something appeared inside
        } else {
          await File(i.file.path).delete();
        }
        freed += i.file.size;
        gone.add(i.file.path);
      } catch (_) {
        fail++;
      }
    }
    _set(() {
      for (final g in _groups) {
        g.items.removeWhere((i) => gone.contains(i.file.path));
      }
      _groups.removeWhere((g) => g.items.isEmpty);
      _sel.removeAll(gone);
      _busy = false;
      _status = 'Deleted ${gone.length} file(s), freed ${humanSize(freed)}.' +
          (fail > 0 ? ' $fail could not be deleted.' : '') +
          (kept > 0 ? ' $kept duplicate(s) kept (original missing).' : '');
    });
  }

  Future<void> _clearAppCache() async {
    _set(() => _status = 'Clearing this app\'s cache...');
    var freed = 0;
    for (final dir in [Directory.systemTemp, await _tempDir()]) {
      if (dir == null || !await dir.exists()) continue;
      try {
        await for (final e in dir.list(recursive: true, followLinks: false)) {
          if (e is File) {
            try {
              freed += (await e.stat()).size;
              await e.delete();
            } catch (_) {}
          }
        }
      } catch (_) {}
    }
    _set(() => _status = 'App cache cleared (${humanSize(freed)}).');
  }

  Future<Directory?> _tempDir() async {
    try {
      return Directory.systemTemp;
    } catch (_) {
      return null;
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(title: const Text('Phone clean-up')),
      body: Column(children: [
        Padding(
          padding: const EdgeInsets.all(12),
          child: Text(
            'Scans your WHOLE phone storage for duplicate, junk, big files and empty folders so you can free real '
            'space. Note: Android does not let ANY app (without root) clear other apps\' cache or free RAM - that '
            'is done in the phone\'s own Settings > Apps / Storage, or the OS does it automatically. This cleans '
            'files, which is the space that actually stays freed.',
            style: TextStyle(color: cs.onSurfaceVariant, fontSize: 13),
          ),
        ),
        if (_status.isNotEmpty)
          Padding(padding: const EdgeInsets.symmetric(horizontal: 12), child: Text(_status)),
        if (_busy) const Padding(padding: EdgeInsets.all(12), child: LinearProgressIndicator()),
        if (_groups.isNotEmpty) ...[
          // one chip per type: how many files and how much space - so it is clear what the list is made of
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 8, 12, 0),
            child: Wrap(spacing: 6, runSpacing: 0, children: [
              for (final g in _groups)
                Chip(
                  visualDensity: VisualDensity.compact,
                  side: BorderSide(color: g.color),
                  label: Text('${g.kind.tag}  ${g.items.length} · ${humanSize(totalBytes(g.items.map((i) => i.file)))}',
                      style: TextStyle(color: g.color, fontSize: 11, fontWeight: FontWeight.w700)),
                ),
            ]),
          ),
          const Padding(
            padding: EdgeInsets.fromLTRB(12, 4, 12, 0),
            child: Text('Delete is PERMANENT - there is no trash. Nothing is deleted until you confirm.',
                style: TextStyle(color: Color(0xFFEF4444), fontSize: 12, fontWeight: FontWeight.w600)),
          ),
          if (_protected > 0)
            Padding(
              padding: const EdgeInsets.fromLTRB(12, 2, 12, 0),
              child: Text(
                  '$_protected files in other apps\' private folders (e.g. WhatsApp backups/databases) were left alone.',
                  style: TextStyle(color: cs.onSurfaceVariant, fontSize: 12)),
            ),
        ],
        Expanded(
          child: ListView(children: [
            for (final g in _groups) ...[
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 14, 16, 0),
                child: Row(children: [
                  Container(width: 4, height: 18, color: g.color),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text('${g.kind.title}  (${g.items.length}, ${humanSize(totalBytes(g.items.map((i) => i.file)))})',
                        style: TextStyle(color: g.color, fontWeight: FontWeight.w700)),
                  ),
                  TextButton(
                    onPressed: () => _set(() {
                      final all = g.items.every((i) => _sel.contains(i.file.path));
                      for (final i in g.items) {
                        all ? _sel.remove(i.file.path) : _sel.add(i.file.path);
                      }
                    }),
                    child: Text(g.items.every((i) => _sel.contains(i.file.path)) ? 'None' : 'All'),
                  ),
                ]),
              ),
              Padding(
                padding: const EdgeInsets.fromLTRB(28, 0, 16, 4),
                child: Text(g.kind.explain, style: TextStyle(color: cs.onSurfaceVariant, fontSize: 12)),
              ),
              for (final i in g.items.take(200))
                CheckboxListTile(
                  dense: true,
                  value: _sel.contains(i.file.path),
                  onChanged: (v) => _set(() => v == true ? _sel.add(i.file.path) : _sel.remove(i.file.path)),
                  title: Text(i.file.name, maxLines: 1, overflow: TextOverflow.ellipsis),
                  subtitle: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text('${i.kind.tag}  ·  ${i.kind == CleanKind.emptyFolder ? 'no files inside' : humanSize(i.file.size)}',
                        style: TextStyle(color: g.color, fontSize: 11, fontWeight: FontWeight.w700)),
                    Text(i.reason, maxLines: 2, overflow: TextOverflow.ellipsis),
                    Text(i.file.path, maxLines: 2, overflow: TextOverflow.ellipsis),
                  ]),
                ),
              if (g.items.length > 200)
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                  child: Text('...and ${g.items.length - 200} more in this group (use "All"/"None" to include them)',
                      style: TextStyle(color: cs.onSurfaceVariant)),
                ),
            ],
            const SizedBox(height: 8),
            Padding(
              padding: const EdgeInsets.all(12),
              child: Wrap(spacing: 8, runSpacing: 8, children: [
                OutlinedButton.icon(
                    onPressed: _busy ? null : _clearAppCache,
                    icon: const Icon(Icons.cached),
                    label: const Text('Clear this app\'s cache')),
                OutlinedButton.icon(
                    onPressed: () => openAppSettings(),
                    icon: const Icon(Icons.settings),
                    label: const Text('Open phone storage settings')),
              ]),
            ),
          ]),
        ),
        SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(12),
            child: Row(children: [
              Expanded(
                child: FilledButton.icon(
                  onPressed: _busy ? null : _scan,
                  icon: const Icon(Icons.search),
                  label: Text(_groups.isEmpty ? 'Scan phone' : 'Scan again'),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: FilledButton.tonalIcon(
                  onPressed: (_busy || _sel.isEmpty) ? null : _deleteSelected,
                  icon: const Icon(Icons.delete_forever),
                  label: Text(_sel.isEmpty ? 'Delete' : 'Delete ${humanSize(_selBytes)}'),
                ),
              ),
            ]),
          ),
        ),
      ]),
    );
  }
}
