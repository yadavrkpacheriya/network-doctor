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
