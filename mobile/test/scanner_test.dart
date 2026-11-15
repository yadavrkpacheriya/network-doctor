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
}
