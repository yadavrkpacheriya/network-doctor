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

class _Group {
  _Group(this.title, this.color, this.files, {this.preselect = false});
  final String title;
  final Color color;
  final List<FileMeta> files;
  final bool preselect;
}

class _CleanScreenState extends State<CleanScreen> {
  bool _busy = false;
  String _status = '';
  int _scanned = 0;
  final _sel = <String>{}; // selected paths to delete
  List<_Group> _groups = [];

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
    final dups = duplicateGroups(all, minSize: 1024); // ignore tiny files
    final free = duplicateFreeable(dups);
    final junk = junkFiles(all);
    final installers = installerFiles(all);
    final large = largeFiles(all);
    final emptyAsFiles = [for (final d in _emptyDirs) FileMeta(d, 0, 0)];
    final groups = <_Group>[
      _Group('Duplicate files', const Color(0xFF7C3AED), free.files, preselect: true),
      _Group('Junk (temp / log / empty)', const Color(0xFFB45309), junk, preselect: true),
      _Group('Leftover installers (APK)', const Color(0xFFBE123C), installers),
      _Group('Empty folders', const Color(0xFF6B7280), emptyAsFiles),
      _Group('Biggest files', const Color(0xFF0369A1), large),
    ]..removeWhere((g) => g.files.isEmpty);
    final sel = <String>{};
    for (final g in groups) {
      if (g.preselect) sel.addAll(g.files.map((f) => f.path));
    }
    _set(() {
      _groups = groups;
      _sel
        ..clear()
        ..addAll(sel);
      _busy = false;
      final total = groups.fold<int>(0, (n, g) => n + totalBytes(g.files));
      _status = groups.isEmpty
          ? 'Nothing to clean - your storage looks tidy. $_scanned files checked.'
          : 'Found ${humanSize(total)} you can review and free, in $_scanned files.';
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

  int get _selBytes {
    var n = 0;
    for (final g in _groups) {
      for (final f in g.files) {
        if (_sel.contains(f.path)) n += f.size;
      }
    }
    return n;
  }

  Future<void> _deleteSelected() async {
    final n = _sel.length;
    if (n == 0) return;
    final ok = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: Text('Delete $n file${n == 1 ? '' : 's'}?'),
        content: Text('This frees ${humanSize(_selBytes)}. Deleted files cannot be recovered from here. '
            'Duplicates keep one copy of each.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('Delete')),
        ],
      ),
    );
    if (ok != true) return;
    _set(() {
      _busy = true;
      _status = 'Deleting...';
    });
    var freed = 0, fail = 0;
    final gone = <String>{};
    for (final g in _groups) {
      final isFolder = g.title == 'Empty folders';
      for (final f in g.files) {
        if (!_sel.contains(f.path)) continue;
        try {
          if (isFolder) {
            await Directory(f.path).delete();
          } else {
            await File(f.path).delete();
          }
          freed += f.size;
          gone.add(f.path);
        } catch (_) {
          fail++;
        }
      }
    }
    _set(() {
      for (final g in _groups) {
        g.files.removeWhere((f) => gone.contains(f.path));
      }
      _groups.removeWhere((g) => g.files.isEmpty);
      _sel.removeAll(gone);
      _busy = false;
      _status = 'Freed ${humanSize(freed)}.' + (fail > 0 ? ' $fail file(s) could not be deleted.' : '');
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
        Expanded(
          child: ListView(children: [
            for (final g in _groups) ...[
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 14, 16, 4),
                child: Row(children: [
                  Container(width: 4, height: 18, color: g.color),
                  const SizedBox(width: 8),
                  Text('${g.title}  (${g.files.length}, ${humanSize(totalBytes(g.files))})',
                      style: TextStyle(color: g.color, fontWeight: FontWeight.w700)),
                  const Spacer(),
                  TextButton(
                    onPressed: () => _set(() {
                      final all = g.files.every((f) => _sel.contains(f.path));
                      for (final f in g.files) {
                        all ? _sel.remove(f.path) : _sel.add(f.path);
                      }
                    }),
                    child: const Text('All'),
                  ),
                ]),
              ),
              for (final f in g.files.take(200))
                CheckboxListTile(
                  dense: true,
                  value: _sel.contains(f.path),
                  onChanged: (v) => _set(() => v == true ? _sel.add(f.path) : _sel.remove(f.path)),
                  title: Text(f.name, maxLines: 1, overflow: TextOverflow.ellipsis),
                  subtitle: Text('${humanSize(f.size)}  ·  ${f.path}', maxLines: 1, overflow: TextOverflow.ellipsis),
                ),
              if (g.files.length > 200)
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
                  child: Text('...and ${g.files.length - 200} more', style: TextStyle(color: cs.onSurfaceVariant)),
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
                  icon: const Icon(Icons.delete_outline),
                  label: Text(_sel.isEmpty ? 'Delete' : 'Free ${humanSize(_selBytes)}'),
                ),
              ),
            ]),
          ),
        ),
      ]),
    );
  }
}
