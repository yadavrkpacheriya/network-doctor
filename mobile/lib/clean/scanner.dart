// Phone clean-up logic - pure Dart over file *metadata*, so it unit-tests without a real filesystem.
//
// Honest about Android: a normal app cannot clear OTHER apps' caches or the system cache (Google removed those
// APIs - that needs root or the phone's own Settings > Storage). What this CAN do is find, in the shared storage
// the user grants access to, the files that are safe to remove: exact DUPLICATES, obvious JUNK (temp/log/leftover
// installers/empty files) and the BIGGEST files - then let the user delete them. The screen does the file I/O;
// everything here is a pure function on a list of FileMeta.

class FileMeta {
  FileMeta(this.path, this.size, this.modifiedMs, {this.hash});
  final String path;
  final int size;
  final int modifiedMs;
  String? hash; // filled in only for files that share a size (so we hash as few files as possible)

  String get name {
    final i = path.lastIndexOf('/');
    return i < 0 ? path : path.substring(i + 1);
  }

  String get ext {
    final n = name;
    final d = n.lastIndexOf('.');
    return d <= 0 ? '' : n.substring(d + 1).toLowerCase();
  }
}

// file kinds that are safe junk to offer for deletion
const junkExts = {'tmp', 'temp', 'log', 'crdownload', 'part', 'partial', 'bak', 'old'};
// leftover app installers pile up in Download and are safe to remove after installing
const installerExts = {'apk', 'xapk', 'obb'};
// folder-name fragments that mean "throwaway"
const junkDirFrags = ['/cache/', '/.thumbnails/', '/.tmp/', '/tmp/', '/log/', '/.trash/', '/lost.dir/'];

/// Which files share a byte size (the cheap pre-filter before hashing - only these need a hash).
List<int> sizesNeedingHash(List<FileMeta> files, {int minSize = 1}) {
  final bySize = <int, int>{};
  for (final f in files) {
    if (f.size >= minSize) {
      bySize[f.size] = (bySize[f.size] ?? 0) + 1;
    }
  }
  return [for (final e in bySize.entries) if (e.value > 1) e.key];
}

/// Groups of exact duplicates (same size AND same hash). Each group has 2+ files; the first is treated as the
/// "keep", the rest as removable. Needs hash filled on the candidates.
List<List<FileMeta>> duplicateGroups(List<FileMeta> files, {int minSize = 1}) {
  final by = <String, List<FileMeta>>{};
  for (final f in files) {
    if (f.size >= minSize && f.hash != null) {
      by.putIfAbsent('${f.size}:${f.hash}', () => []).add(f);
    }
  }
  final out = <List<FileMeta>>[];
  for (final g in by.values) {
    if (g.length > 1) {
      g.sort((a, b) => a.modifiedMs.compareTo(b.modifiedMs)); // keep the oldest original, offer the newer copies
      out.add(g);
    }
  }
  out.sort((a, b) => (b[0].size * (b.length - 1)).compareTo(a[0].size * (a.length - 1))); // biggest savings first
  return out;
}

/// The removable copies (every duplicate except one kept per group) and how many bytes that frees.
({List<FileMeta> files, int bytes}) duplicateFreeable(List<List<FileMeta>> groups) {
  final files = <FileMeta>[];
  var bytes = 0;
  for (final g in groups) {
    for (var i = 1; i < g.length; i++) {
      files.add(g[i]);
      bytes += g[i].size;
    }
  }
  return (files: files, bytes: bytes);
}

bool isJunk(FileMeta f) {
  if (f.size == 0) return true; // empty files
  if (junkExts.contains(f.ext)) return true;
  final p = f.path.toLowerCase();
  for (final frag in junkDirFrags) {
    if (p.contains(frag)) return true;
  }
  return false;
}

/// Junk files (temp/log/empty/throwaway-folder). Installers are returned separately because deleting an APK is
/// only safe once installed - the user should see those as their own group.
List<FileMeta> junkFiles(List<FileMeta> files) => [for (final f in files) if (isJunk(f)) f];

/// Leftover installers (.apk/.xapk/.obb) - usually safe to remove after installing the app.
List<FileMeta> installerFiles(List<FileMeta> files) =>
    [for (final f in files) if (installerExts.contains(f.ext)) f];

/// The biggest files, so the user can clear space fast. Excludes anything already flagged junk.
List<FileMeta> largeFiles(List<FileMeta> files, {int minBytes = 50 * 1024 * 1024, int limit = 50}) {
  final big = [for (final f in files) if (f.size >= minBytes && !isJunk(f)) f]..sort((a, b) => b.size.compareTo(a.size));
  return big.take(limit).toList();
}

int totalBytes(Iterable<FileMeta> files) {
  var n = 0;
  for (final f in files) {
    n += f.size;
  }
  return n;
}

/// "1.4 GB", "820 MB", "12 KB" - friendly size.
String humanSize(int bytes) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  var b = bytes.toDouble();
  var u = 0;
  while (b >= 1024 && u < units.length - 1) {
    b /= 1024;
    u++;
  }
  final s = b >= 100 || u == 0 ? b.toStringAsFixed(0) : b.toStringAsFixed(1);
  return '$s ${units[u]}';
}


// ---------------------------------------------------------------------------------------------------------------
// Clean-up PLAN: every file lands in exactly ONE group, each with a plain reason, so the screen can say clearly
// what a file is (duplicate / junk / installer / empty folder / big file) and nothing is counted or deleted twice.
// ---------------------------------------------------------------------------------------------------------------

enum CleanKind { duplicate, junk, installer, emptyFolder, big }

extension CleanKindInfo on CleanKind {
  /// Short tag shown on every row.
  String get tag {
    switch (this) {
      case CleanKind.duplicate:
        return 'DUPLICATE';
      case CleanKind.junk:
        return 'JUNK';
      case CleanKind.installer:
        return 'INSTALLER';
      case CleanKind.emptyFolder:
        return 'EMPTY FOLDER';
      case CleanKind.big:
        return 'BIG FILE';
    }
  }

  /// Group title.
  String get title {
    switch (this) {
      case CleanKind.duplicate:
        return 'Duplicate files';
      case CleanKind.junk:
        return 'Junk (temp / log / empty)';
      case CleanKind.installer:
        return 'Leftover installers (APK)';
      case CleanKind.emptyFolder:
        return 'Empty folders';
      case CleanKind.big:
        return 'Biggest files';
    }
  }

  /// One plain line under the group title: what it is and what happens to it.
  String get explain {
    switch (this) {
      case CleanKind.duplicate:
        return 'Extra copies of a file you already have. One original of each is KEPT; only the extra copy is deleted.';
      case CleanKind.junk:
        return 'Temp, log, empty and cache-folder files. Normally safe to delete.';
      case CleanKind.installer:
        return 'Old APK installers. Safe once the app is installed. Not ticked by default.';
      case CleanKind.emptyFolder:
        return 'Folders with nothing inside. Deleting frees no space, only tidies up. Not ticked by default.';
      case CleanKind.big:
        return 'Your own large files (videos etc.). Check each one - they are NOT junk. Not ticked by default.';
    }
  }

  /// Only the clearly-safe groups start ticked.
  bool get preselect => this == CleanKind.duplicate || this == CleanKind.junk;
}

class CleanItem {
  CleanItem(this.file, this.kind, this.reason, {this.keepPath});
  final FileMeta file;
  final CleanKind kind;

  /// Plain-language reason shown on the row ("Same content as ...", "Empty file", ...).
  final String reason;

  /// For duplicates: the copy that is kept.
  final String? keepPath;
}

class CleanPlan {
  CleanPlan(this.items, this.protectedCount);

  /// Items per group, in display order (empty groups omitted).
  final Map<CleanKind, List<CleanItem>> items;

  /// Files seen but deliberately left alone (other apps' private folders, e.g. WhatsApp chat backups/databases).
  final int protectedCount;

  int get totalCount => items.values.fold(0, (n, l) => n + l.length);
  int get totalBytes => items.values.fold(0, (n, l) => n + l.fold(0, (m, i) => m + i.file.size));
}

/// Other apps' private area inside shared storage: `/Android/media/<app>/...`. Android keeps app internals there
/// (chat backups, databases, caches). Only that app's own user-media folder (a sub-folder named `Media`, like
/// WhatsApp's photos/videos/voice notes) is open for duplicate/big-file clean-up; everything else is left alone.
bool isProtectedPath(String path) {
  final lower = path.toLowerCase();
  const marker = '/android/media/';
  final i = lower.indexOf(marker);
  if (i < 0) return false;
  final segs = lower.substring(i + marker.length).split('/');
  if (segs.length < 2) return true; // the app folder itself
  return !segs.skip(1).contains('media');
}

/// Why a file counts as junk, or null if it does not.
String? junkReason(FileMeta f) {
  if (f.path.toLowerCase().contains('/android/media/')) return null; // other apps' media: never "junk" by guess
  if (f.size == 0) return 'Empty file (0 bytes)';
  if (junkExts.contains(f.ext)) return 'Temporary/log file (.${f.ext})';
  final p = f.path.toLowerCase();
  for (final frag in junkDirFrags) {
    if (p.contains(frag)) return 'Inside a cache/temp folder';
  }
  return null;
}

/// Builds the plan. Each file goes into ONE group (priority: junk, duplicate, installer, big), so sizes are never
/// double counted and a file is never deleted twice. Needs `hash` filled on same-size candidates.
CleanPlan buildCleanPlan(List<FileMeta> all, List<String> emptyDirs) {
  var protectedCount = 0;
  final safe = <FileMeta>[];
  for (final f in all) {
    if (isProtectedPath(f.path)) {
      protectedCount++;
    } else {
      safe.add(f);
    }
  }
  final out = {for (final k in CleanKind.values) k: <CleanItem>[]};
  final claimed = <String>{};

  for (final f in safe) {
    final r = junkReason(f);
    if (r != null) {
      out[CleanKind.junk]!.add(CleanItem(f, CleanKind.junk, r));
      claimed.add(f.path);
    }
  }
  final rest = [for (final f in safe) if (!claimed.contains(f.path)) f];

  for (final g in duplicateGroups(rest, minSize: 1024)) {
    final keep = g.first;
    for (var i = 1; i < g.length; i++) {
      out[CleanKind.duplicate]!
          .add(CleanItem(g[i], CleanKind.duplicate, 'Same content as: ${keep.path}  (that one is kept)', keepPath: keep.path));
      claimed.add(g[i].path);
    }
  }

  for (final f in rest) {
    if (!claimed.contains(f.path) && installerExts.contains(f.ext)) {
      out[CleanKind.installer]!.add(CleanItem(f, CleanKind.installer, 'Leftover installer (.${f.ext})'));
      claimed.add(f.path);
    }
  }

  for (final f in largeFiles([for (final f in rest) if (!claimed.contains(f.path)) f])) {
    out[CleanKind.big]!.add(CleanItem(f, CleanKind.big, 'Large file (${humanSize(f.size)}) - your own file, check before deleting'));
  }

  for (final d in emptyDirs) {
    if (!isProtectedPath(d)) {
      out[CleanKind.emptyFolder]!.add(CleanItem(FileMeta(d, 0, 0), CleanKind.emptyFolder, 'Empty folder'));
    }
  }

  out.removeWhere((k, v) => v.isEmpty);
  return CleanPlan(out, protectedCount);
}

/// Duplicates are only deleted while their kept original is NOT also being deleted, so one copy always survives.
/// Returns the items to delete and the duplicates held back for that reason.
({List<CleanItem> toDelete, List<CleanItem> heldBack}) safeToDelete(Iterable<CleanItem> chosen) {
  final list = chosen.toList();
  final del = {for (final c in list) c.file.path};
  final ok = <CleanItem>[], held = <CleanItem>[];
  for (final c in list) {
    if (c.kind == CleanKind.duplicate && del.contains(c.keepPath)) {
      held.add(c);
    } else {
      ok.add(c);
    }
  }
  return (toDelete: ok, heldBack: held);
}
