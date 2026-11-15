import 'package:flutter_test/flutter_test.dart';
import 'package:network_doctor/clean/scanner.dart';

FileMeta f(String path, int size, {int mod = 0, String? hash}) => FileMeta(path, size, mod, hash: hash);

void main() {
  test('only same-size files need hashing', () {
    final sizes = sizesNeedingHash([f('/a', 100), f('/b', 100), f('/c', 200)]);
    expect(sizes, [100]);
  });

  test('duplicate groups keep the oldest and free the rest', () {
    final files = [
      f('/dl/song.mp3', 1000, mod: 100, hash: 'x'),
      f('/wa/song.mp3', 1000, mod: 200, hash: 'x'), // newer copy
      f('/other.mp3', 1000, mod: 50, hash: 'y'), // same size, different content -> not a dup
    ];
    final groups = duplicateGroups(files);
    expect(groups.length, 1);
    expect(groups[0].first.path, '/dl/song.mp3'); // oldest kept
    final free = duplicateFreeable(groups);
    expect(free.files.length, 1);
    expect(free.files[0].path, '/wa/song.mp3');
    expect(free.bytes, 1000);
  });

  test('junk detects temp/log/empty/cache-folder, installers are separate', () {
    final files = [
      f('/a.tmp', 10),
      f('/b.log', 10),
      f('/empty', 0),
      f('/Android/data/x/cache/img', 10),
      f('/Download/app.apk', 9999),
      f('/Pictures/photo.jpg', 10),
    ];
    final junk = junkFiles(files).map((x) => x.path).toSet();
    expect(junk.contains('/a.tmp'), true);
    expect(junk.contains('/b.log'), true);
    expect(junk.contains('/empty'), true);
    expect(junk.contains('/Android/data/x/cache/img'), true);
    expect(junk.contains('/Pictures/photo.jpg'), false);
    expect(junk.contains('/Download/app.apk'), false); // installer, not generic junk
    expect(installerFiles(files).single.path, '/Download/app.apk');
  });

  test('large files sorted big-first and exclude junk', () {
    final big = largeFiles([
      f('/movie.mp4', 200 * 1024 * 1024),
      f('/clip.mp4', 60 * 1024 * 1024),
      f('/small.jpg', 1024),
      f('/huge.tmp', 500 * 1024 * 1024), // junk -> excluded even though huge
    ]);
    expect(big.map((x) => x.name).toList(), ['movie.mp4', 'clip.mp4']);
  });

  test('humanSize is friendly', () {
    expect(humanSize(0), '0 B');
    expect(humanSize(1536), '1.5 KB');
    expect(humanSize(200 * 1024 * 1024), '200 MB');
  });

  test('plan: every file is in exactly one group, with a reason', () {
    final files = [
      f('/Download/a.tmp', 10), // junk
      f('/dl/song.mp3', 5000, mod: 1, hash: 'x'), // kept original
      f('/wa/song.mp3', 5000, mod: 2, hash: 'x'), // duplicate
      f('/Download/app.apk', 9000),
      f('/Movies/film.mp4', 200 * 1024 * 1024),
    ];
    final plan = buildCleanPlan(files, ['/Pictures/empty']);
    expect(plan.items[CleanKind.junk]!.single.file.path, '/Download/a.tmp');
    final dup = plan.items[CleanKind.duplicate]!.single;
    expect(dup.file.path, '/wa/song.mp3');
    expect(dup.keepPath, '/dl/song.mp3');
    expect(dup.reason.contains('/dl/song.mp3'), true);
    expect(plan.items[CleanKind.installer]!.single.file.name, 'app.apk');
    expect(plan.items[CleanKind.big]!.single.file.name, 'film.mp4');
    expect(plan.items[CleanKind.emptyFolder]!.single.file.path, '/Pictures/empty');
    final paths = [for (final l in plan.items.values) for (final i in l) i.file.path];
    expect(paths.toSet().length, paths.length); // nothing listed twice
  });

  test('plan: a junk copy never leaves zero copies (junk is removed first, the other copy stays)', () {
    final files = [
      f('/Download/cache/x.jpg', 5000, mod: 1, hash: 'h'), // oldest, but in a cache folder -> junk
      f('/Pictures/x.jpg', 5000, mod: 2, hash: 'h'),
    ];
    final plan = buildCleanPlan(files, []);
    expect(plan.items[CleanKind.junk]!.single.file.path, '/Download/cache/x.jpg');
    expect(plan.items.containsKey(CleanKind.duplicate), false); // /Pictures/x.jpg stays untouched
  });

  test('other apps\' private folders are protected, WhatsApp user media is not', () {
    const wa = '/storage/emulated/0/Android/media/com.whatsapp';
    expect(isProtectedPath('$wa/WhatsApp/Backups/msgstore.db.crypt14'), true);
    expect(isProtectedPath('$wa/WhatsApp/Databases/msgstore.db'), true);
    expect(isProtectedPath('$wa/WhatsApp/.Shared/abc'), true);
    expect(isProtectedPath('$wa/WhatsApp/Media/WhatsApp Images/IMG-1.jpg'), false);
    expect(isProtectedPath('/storage/emulated/0/DCIM/Camera/a.jpg'), false);
    final plan = buildCleanPlan([
      f('$wa/WhatsApp/cache/XnxhoeEf4W564n', 24), // looks like junk, but it is WhatsApp's own file
      f('$wa/WhatsApp/x', 0),
    ], ['$wa/WhatsApp/empty']);
    expect(plan.items.isEmpty, true);
    expect(plan.protectedCount, 2);
  });

  test('a duplicate is held back if its kept original is also being deleted', () {
    final keep = CleanItem(f('/a/big.mp4', 9999), CleanKind.big, 'big');
    final dup = CleanItem(f('/b/big.mp4', 9999), CleanKind.duplicate, 'dup', keepPath: '/a/big.mp4');
    final r = safeToDelete([keep, dup]);
    expect(r.toDelete.map((i) => i.file.path), ['/a/big.mp4']);
    expect(r.heldBack.single.file.path, '/b/big.mp4');
    expect(safeToDelete([dup]).toDelete.length, 1); // original not selected -> fine to delete the extra copy
  });
}
