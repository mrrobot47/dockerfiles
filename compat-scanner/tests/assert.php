<?php
// Checks the outputs run.sh collected in <dir>. Runs inside the scanner image.

$dir   = $argv[1];
$fails = 0;
$count = 0;

function check( bool $ok, string $what ) {
	global $fails, $count;
	$count++;
	if ( ! $ok ) {
		$fails++;
	}
	echo( $ok ? 'ok   ' : 'FAIL ' ), $what, "\n";
}

function out( string $name ): array {
	global $dir;
	$raw = (string) @file_get_contents( "$dir/$name.stdout" );
	check( 1 === substr_count( $raw, "\n" ) && "\n" === substr( $raw, -1 ), "$name: stdout is one line" );
	$doc = json_decode( $raw, true );
	check( is_array( $doc ), "$name: stdout is a JSON object" );
	return is_array( $doc ) ? $doc : [];
}

function report( string $name ): array {
	global $dir;
	$doc = json_decode( (string) @file_get_contents( "$dir/$name.report.json" ), true );
	check( is_array( $doc ), "$name: report.json is a JSON object" );
	return is_array( $doc ) ? $doc : [];
}

function rc( string $name ): int {
	global $dir;
	return (int) trim( (string) @file_get_contents( "$dir/$name.rc" ) );
}

function eq( $actual, $expected, string $what ) {
	$ok = $actual === $expected;
	check( $ok, $what . ( $ok ? '' : ' (got ' . json_encode( $actual ) . ', want ' . json_encode( $expected ) . ')' ) );
}

function comp_rows( array $report ): array {
	$rows = [];
	foreach ( $report['components'] ?? [] as $c ) {
		$rows[] = [ $c['type'], $c['slug'], $c['branch'], $c['name'], $c['version'], $c['files'], $c['errors'], $c['warnings'] ];
	}
	return $rows;
}

/** The value, or 'missing' when the key is absent (?? can't tell null from absent). */
function field( array $doc, string $key ) {
	return array_key_exists( $key, $doc ) ? $doc[ $key ] : 'missing';
}

/** The component with this type, slug and branch, or []. */
function comp_of( array $report, string $type, string $slug, ?string $branch = null ): array {
	foreach ( $report['components'] ?? [] as $c ) {
		if ( $c['type'] === $type && $c['slug'] === $slug && $c['branch'] === $branch ) {
			return $c;
		}
	}
	return [];
}

function raw( string $name ): string {
	global $dir;
	return (string) @file_get_contents( "$dir/$name" );
}

/** A tool_error run: one JSON line, the detail, the exit code, and report.json equal to stdout. */
function tool_error( string $name, string $detail_prefix, int $code, bool $report = true ): array {
	$doc = out( $name );
	eq( rc( $name ), $code, "$name: exit $code" );
	eq( [ $doc['status'] ?? null, field( $doc, 'safe_to_upgrade' ) ], [ 'tool_error', null ], "$name: tool_error, no verdict" );
	check( 0 === strpos( $doc['detail'] ?? '', $detail_prefix ), "$name: detail starts with '$detail_prefix' (" . ( $doc['detail'] ?? '' ) . ')' );
	if ( $report ) {
		eq( report( $name ), $doc, "$name: report.json equals stdout" );
		eq( trim( raw( "$name.outdir" ) ), './report.json', "$name: /out holds only report.json" );
	}
	return $doc;
}

function summary_of( array $report ): array {
	unset( $report['components'], $report['not_checked'], $report['wordpress_installs'], $report['excluded_old_releases'], $report['phars'], $report['phar_named_by'] );
	return $report;
}

function without_duration( array $doc ): array {
	unset( $doc['duration_s'] );
	return $doc;
}

// ----------------------------------------------------------------- full tree

$full = out( 'full' );
$rep  = report( 'full' );
eq( rc( 'full' ), 0, 'full: exit 0' );
eq( $full['status'] ?? null, 'ok', 'full: status ok' );
eq( field( $full, 'safe_to_upgrade' ), false, 'full: safe_to_upgrade false' );
eq( array_keys( $full ), [ 'v', 'status', 'site', 'target', 'safe_to_upgrade', 'errors', 'warnings', 'files_checked', 'files_not_checked', 'php_bytes', 'components_checked', 'components_with_errors', 'duration_s', 'tool' ], 'full: summary keys and order' );
eq( [ $full['v'], $full['site'], $full['target'] ], [ 1, 'fixture.test', '8.4' ], 'full: v, site, target' );
eq( [ $full['errors'], $full['warnings'], $full['files_checked'], $full['files_not_checked'], $full['components_checked'], $full['components_with_errors'] ], [ 1133, 3, 49, 4, 23, 19 ], 'full: counts' );
check( $full['php_bytes'] > 0 && is_int( $full['duration_s'] ), 'full: php_bytes and duration_s' );
eq( array_keys( $full['tool'] ), [ 'phpcs', 'phpcompatibility', 'phpcompatibility_wp', 'image' ], 'full: tool keys' );
check( 0 === strpos( $full['tool']['phpcs'], '4.0.' ) && '10.0.0-alpha3' === $full['tool']['phpcompatibility'] && '3.0.0-alpha3' === $full['tool']['phpcompatibility_wp'], 'full: tool versions' );
eq( summary_of( $rep ), $full, 'full: report summary equals stdout' );

eq(
	comp_rows( $rep ),
	[
		[ 'plugin', 'many', null, 'Many', null, 1, 1100, 0 ],
		[ 'other', '', null, null, null, 9, 6, 0 ],
		[ 'plugin', 'annotated', null, 'Annotated', null, 5, 5, 0 ],
		[ 'plugin', 'order', null, 'Order', null, 3, 3, 0 ],
		[ 'plugin', 'cachey', null, 'Cachey', null, 4, 2, 0 ],
		[ 'plugin', 'clean', null, 'Clean Plugin', null, 3, 2, 0 ],
		[ 'plugin', 'hello.php', null, 'Hello Single', '0.9', 1, 2, 0 ],
		[ 'plugin', 'legacy', null, 'Legacy Plugin', '1.2.3', 2, 2, 0 ],
		[ 'plugin', 'broken', null, 'Broken', null, 1, 1, 0 ],
		[ 'plugin', 'bundled', null, 'Bundled', null, 2, 1, 0 ],
		[ 'plugin', 'ctl', null, "Ctl\u{FFFD}evil\u{FFFD}2J\u{FFFD}", null, 2, 1, 0 ],
		[ 'plugin', 'hardlink', null, 'Hardlink', null, 1, 1, 0 ],
		[ 'plugin', 'incl', null, 'Incl', null, 2, 1, 0 ],
		[ 'plugin', 'utf', null, 'Utf', null, 2, 1, 0 ],
		[ 'plugin', 'branchy', 'main', 'Branchy', '0.1', 1, 1, 0 ],
		[ 'theme', 'demo', null, 'Demo Theme', '2.1', 1, 1, 0 ],
		[ 'directory', 'htdocs', null, null, null, 1, 1, 0 ],
		[ 'other', 'wp-config.php', null, null, null, 1, 1, 0 ],
		[ 'other', '', 'main', null, null, 2, 1, 0 ],
		[ 'plugin', 'warnonly', null, 'Warn Only', '3.0', 1, 0, 2 ],
		[ 'mu-plugin', 'mu-plugins', null, null, null, 2, 0, 1 ],
		[ 'plugin', 'loop', null, 'Loop', null, 1, 0, 0 ],
		[ 'theme', 'fifo', null, 'fifo', null, 1, 0, 0 ],
	],
	'full: components, grouping, names, versions, branches, order'
);

$total = 0;
$files = [];
foreach ( $rep['components'] ?? [] as $c ) {
	$n = count( $c['findings'] );
	$total += $n;
	check( $n === $c['errors'] + $c['warnings'], "full: {$c['slug']}/{$c['branch']} lists every finding ($n)" );
	$sorted = $c['findings'];
	usort(
		$sorted,
		static function ( $a, $b ) {
			return [ 'ERROR' === $a['type'] ? 0 : 1, $a['file'], $a['line'] ] <=> [ 'ERROR' === $b['type'] ? 0 : 1, $b['file'], $b['line'] ];
		}
	);
	check( array_map( 'json_encode', $sorted ) === array_map( 'json_encode', $c['findings'] ), "full: {$c['slug']}/{$c['branch']} findings ordered" );
	if ( $c['findings'] ) {
		eq( array_keys( $c['findings'][0] ), [ 'file', 'line', 'type', 'source', 'message' ], 'full: finding keys' );
	}
	foreach ( $c['findings'] as $f ) {
		$files[ $c['type'] . ':' . $c['slug'] . ':' . $c['branch'] . ':' . $f['file'] ] = true;
	}
}
eq( $total, 1136, 'full: report has every finding (>1,000, uncapped)' );
eq( count( $rep['components'][0]['findings'] ?? [] ), 1100, 'full: 1,100 findings of one component all listed' );

ksort( $files );
$expect_files = [
	'other:::cache/c.php',
	'other:::languages/de_DE.l10n.php',
	'other:::lib/helper.php',
	'other:::node_modules/n.php',
	'other:::upgrade/u.php',
	'other:::uploads/evil.php',
	'other::main:uploads/evil.php',
	'plugin:clean::.git/hooks/y.php',
	'plugin:clean::node_modules/pkg/x.php',
	'other:wp-config.php::htdocs/wp-config.php',
	'directory:htdocs::wp-content/plugins/outside/outside.php',
	'plugin:annotated::annotated.php',
	'plugin:annotated::disable.php',
	'plugin:annotated::inline.php',
	'plugin:annotated::late.php',
	'plugin:annotated::whole.php',
	'plugin:hardlink::h1.php',
	'plugin:incl::link.php',
	"plugin:order::a\u{FFFD}b.php",
	'plugin:order::b.php',
	'plugin:order::c.php',
	"plugin:ctl::x\u{FFFD}gpj\u{FFFD}[31m.php",
	'plugin:branchy:main:branchy.php',
	'plugin:broken::broken.php',
	'plugin:bundled::vendor/acme/lib/Old.php',
	'plugin:cachey::cache/c.php',
	'plugin:cachey::plugins/p.php',
	'plugin:hello.php::hello.php',
	'plugin:legacy::legacy.php',
	'plugin:many::many.php',
	"plugin:utf::bad\u{FFFD}\u{FFFD}name.php",
	'plugin:warnonly::warnonly.php',
	'mu-plugin:mu-plugins::sub/x.php',
	'theme:demo::functions.php',
];
sort( $expect_files );
eq( array_keys( $files ), $expect_files, 'full: findings per file (paths relative to the component; core and links to core/ancestors absent; code beside the WordPress root present; code files in skipped dirs, languages/ and a branch\'s uploads/ checked; invalid UTF-8 and control characters substituted)' );

$legacy = comp_of( $rep, 'plugin', 'legacy' )['findings'] ?? [];
eq(
	array_map( static function ( $f ) { return $f['line'] . ' ' . $f['source']; }, $legacy ),
	[ '6 PHPCompatibility.FunctionUse.RemovedFunctions.create_functionDeprecatedRemoved', '7 PHPCompatibility.FunctionUse.RemovedFunctions.eachDeprecatedRemoved' ],
	'full: legacy findings'
);
eq( array_intersect_key( comp_of( $rep, 'plugin', 'broken' )['findings'][0] ?? [], [ 'line' => 0, 'source' => 0 ] ), [ 'line' => 3, 'source' => 'CompatScanner.Syntax.ParseError' ], 'full: a syntax error is the lint\'s finding, on its line' );
eq( [ $rep['wordpress_installs'] ?? null, $rep['excluded_old_releases'] ?? null, $rep['phars'] ?? null, field( $rep, 'phar_named_by' ) ], [ [ [ 'dir' => '/var/www/htdocs/releases/1', 'version' => '', 'live' => true ] ], [], [], null ], 'full: the live root (no version.php: unknown version), no old release, no phar' );
eq( array_column( comp_of( $rep, 'plugin', 'annotated' )['findings'] ?? [], 'file' ), [ 'annotated.php', 'disable.php', 'inline.php', 'late.php', 'whole.php' ], 'full: annotations ignored (targeted phpcs:ignore, phpcs:ignoreFile on line 1 and line 6, blanket phpcs:disable, bare phpcs:ignore)' );
eq( array_column( comp_of( $rep, 'plugin', 'order' )['findings'] ?? [], 'file' ), [ "a\u{FFFD}b.php", 'b.php', 'c.php' ], 'full: findings in file order with a STDIN file first' );
eq( array_column( comp_of( $rep, 'plugin', 'incl' )['findings'] ?? [], 'file' ), [ 'link.php' ], 'full: .php link to a .inc file checked under the link name' );
eq( comp_of( $rep, 'plugin', 'hardlink' )['files'] ?? null, 1, 'full: hard-linked file counted once' );
eq( [ comp_of( $rep, 'plugin', 'index.php' ), comp_of( $rep, 'other', '' )['files'] ?? null ], [ [], 9 ], 'full: header-less plugins/index.php is in other, not a plugin' );
$raw = raw( 'full.report.json' );
check( false === strpos( $raw, "\u{202E}" ) && false === strpos( $raw, "\u{9B}" ) && false === strpos( $raw, "\x7f" ) && false === strpos( $raw, '\\u001b' ), 'full: no bidi, C1, DEL or escape characters in report.json' );

eq(
	$rep['not_checked'] ?? null,
	[
		[ 'type' => 'plugin', 'slug' => 'dangling', 'branch' => null, 'file' => 'dangling', 'reason' => 'unreadable' ],
		[ 'type' => 'plugin', 'slug' => 'locked', 'branch' => null, 'file' => './', 'reason' => 'unreadable' ],
		[ 'type' => 'other', 'slug' => '', 'branch' => 'main', 'file' => 'cache', 'reason' => 'unreadable' ],
		[ 'type' => 'other', 'slug' => '', 'branch' => 'main', 'file' => 'upgrade', 'reason' => 'unreadable' ],
	],
	'full: not_checked has the dangling link, the unlistable dir, and bad links in a branch (skipped names are no skip there)'
);
eq( trim( (string) file_get_contents( "$dir/full.outdir" ) ), "./manifest.json\n./report.json", 'full: /out holds only manifest.json and report.json' );

// ---------------------------------------------------------- verdict variants

$clean = out( 'clean' );
eq( [ $clean['status'] ?? null, field( $clean, 'safe_to_upgrade' ), $clean['errors'] ?? null, $clean['warnings'] ?? null, $clean['files_not_checked'] ?? null ], [ 'ok', true, 0, 3, 0 ], 'clean: true with warnings only' );
eq( report( 'clean' )['not_checked'] ?? null, [], 'clean: not_checked empty (skipped dirs without code are silent)' );

$null = out( 'null' );
eq( [ $null['status'] ?? null, field( $null, 'safe_to_upgrade' ), $null['errors'] ?? null, $null['files_not_checked'] ?? null ], [ 'ok', null, 0, 2 ], 'null: null when only unreadable entries' );

// ------------------------------------------------------------------ retries

foreach ( [ 'batchmem' => 'single-file step', 'filemem' => 'higher-memory retry' ] as $name => $what ) {
	$doc = out( $name );
	$r   = report( $name );
	eq( without_duration( $doc ), without_duration( $full ), "$name: summary equals the normal run ($what)" );
	eq( $r['components'] ?? null, $rep['components'] ?? [], "$name: findings equal the normal run" );
	eq( $r['not_checked'] ?? null, $rep['not_checked'] ?? [], "$name: not_checked equals the normal run" );
}

$all = out( 'allmem' );
$r   = report( 'allmem' );
eq( [ field( $all, 'safe_to_upgrade' ), $all['errors'] ?? null, $all['files_checked'] ?? null, $all['files_not_checked'] ?? null ], [ false, 1, 1, 52 ], 'allmem: only the lint\'s finding checked' );
$reasons = array_count_values( array_column( $r['not_checked'] ?? [], 'reason' ) );
eq( $reasons, [ 'unreadable' => 4, 'memory' => 48 ], 'allmem: every other file in not_checked with reason memory' );

$oom = out( 'oom' );
eq( field( $oom, 'safe_to_upgrade' ), null, 'oom: verdict null' );
eq( report( 'oom' )['not_checked'] ?? null, [ [ 'type' => 'plugin', 'slug' => 'big', 'branch' => null, 'file' => 'big.php', 'reason' => 'memory' ] ], 'oom: a kernel OOM kill is reason memory (' . trim( preg_replace( '/\s+/', ' ', raw( 'oom.stderr' ) ) ) . ')' );

// ------------------------------------------------------------------ timeout

$t = out( 'timeout' );
eq( rc( 'timeout' ), 1, 'timeout: exit 1' );
eq( array_keys( $t ), [ 'v', 'status', 'site', 'target', 'safe_to_upgrade', 'detail' ], 'timeout: reduced keys only, no counts' );
eq( [ $t['status'] ?? null, field( $t, 'safe_to_upgrade' ) ], [ 'tool_error', null ], 'timeout: tool_error, no verdict' );
check( (bool) preg_match( '#^timed out after 1 s at htdocs/\S+\.php, with \d+ of \d+ files checked; run it again with a longer --timeout$#', $t['detail'] ?? '' ), 'timeout: detail names the file and how far the scan got (' . ( $t['detail'] ?? '' ) . ')' );
eq( report( 'timeout' ), $t, 'timeout: report.json equals stdout, no not_checked' );

// ------------------------------------------------------- memory and size bounds

$flood = out( 'flood' );
eq( [ $flood['status'] ?? null, $flood['errors'] ?? null ], [ 'ok', 20000 ], 'flood: 20,000 findings with a 12M entrypoint' );
eq( count( comp_of( report( 'flood' ), 'plugin', 'flood' )['findings'] ?? [] ), 20000, 'flood: every finding in the report' );

$wide = out( 'wide-est' );
eq( [ $wide['status'] ?? null, $wide['php_files'] ?? null ], [ 'ok', 20000 ], 'wide-est: 20,000 files listed with an 8M entrypoint' );

$fatal = tool_error( 'fatal', 'internal error: Allowed memory size', 1 );
tool_error( 'flood-cap', 'report larger than 1024 bytes', 1 );
// SIGXFSZ is 25, or 153 with the core flag a piped core_pattern sets; EFBIG (exit 255) if SIGXFSZ is ignored.
$fc_err = raw( 'flood-cap.stderr' );
$fc_rc  = preg_match( '/\] batch \d+ files rc=(\d+)/', $fc_err, $m ) ? (int) $m[1] : null;
check( null !== $fc_rc && ( 25 === ( $fc_rc & 0x7f ) || ( 255 === $fc_rc && false !== strpos( $fc_err, 'errno=27 File too large' ) ) ), "flood-cap: PHPCS stopped at the file size limit (rc=$fc_rc)" );
check( false !== strpos( raw( 'flood-cap.stderr' ), 'core limit 0' ), 'flood-cap: core dumps disabled' );
tool_error( 'full-cap', 'report larger than 100000 bytes', 1 );
$wc = out( 'wide-cap' );
eq( [ $wc['status'] ?? null, $wc['files_checked'] ?? null ], [ 'ok', 20000 ], 'wide-cap: no cap on the file list, only on findings' );
tool_error( 'fullout', 'could not write', 1, false );

// ------------------------------------------------------------- wp-config.php

foreach ( [ 'wpcfg-dir' => [ 'htdocs/wp-config.php', 'PHPCompatibility.FunctionUse.RemovedFunctions.create_functionDeprecatedRemoved' ], 'wpcfg-parent' => [ 'wp-config.php', 'PHPCompatibility.FunctionUse.RemovedFunctions.eachDeprecatedRemoved' ] ] as $name => list( $file, $source ) ) {
	$doc = out( $name );
	$c   = comp_of( report( $name ), 'other', 'wp-config.php' );
	eq( [ $doc['errors'] ?? null, $doc['files_checked'] ?? null ], 'wpcfg-dir' === $name ? [ 2, 3 ] : [ 1, 2 ], "$name: every wp-config.php in /var/www is scanned" );
	eq( [ $c['files'] ?? null, array_column( $c['findings'] ?? [], 'file' ), array_column( $c['findings'] ?? [], 'source' ) ], [ 1, [ $file ], [ $source ] ], "$name: component other/wp-config.php, file $file" );
}

// ------------------------------------------------------------ php releases

$pr = out( 'php-rel' );
eq( [ $pr['errors'] ?? null, $pr['files_checked'] ?? null ], [ 2, 5 ], 'php-rel: only the live release (and shared/, releases/ files) scanned' );
eq(
	comp_rows( report( 'php-rel' ) ),
	[
		[ 'directory', 'current', null, null, null, 2, 1, 0 ],
		[ 'directory', 'shared', null, null, null, 1, 1, 0 ],
		[ 'directory', 'releases', null, null, null, 1, 0, 0 ],
		[ 'other', '', null, null, null, 1, 0, 0 ],
	],
	'php-rel: components (old release 1 absent)'
);
$e = out( 'est-php-rel' );
eq( [ $e['php_files'] ?? null, $e['php_bytes'] ?? null, $e['components'] ?? null ], [ $pr['files_checked'] + $pr['files_not_checked'], $pr['php_bytes'] ?? null, $pr['components_checked'] ?? null ], 'est-php-rel: counts equal the scan' );
eq( [ out( 'php-rel-link' )['errors'] ?? null ], [ 3 ], 'php-rel-link: symlinked releases/ is not the layout, every release scanned' );

// --------------------------------------------------------------- php site

$php = out( 'php' );
$r   = report( 'php' );
eq( [ $php['status'] ?? null, field( $php, 'safe_to_upgrade' ), $php['errors'] ?? null, $php['warnings'] ?? null, $php['files_checked'] ?? null ], [ 'ok', false, 5, 1, 9 ], 'php: verdict and counts (root is htdocs, WordPress skips not applied; code in node_modules/ and .git/ checked)' );
eq(
	comp_rows( $r ),
	[
		[ 'other', '', null, null, null, 3, 2, 0 ],
		[ 'directory', 'app', null, null, null, 2, 1, 1 ],
		[ 'directory', 'uploads', null, null, null, 1, 1, 0 ],
		[ 'directory', 'vendor', null, null, null, 1, 1, 0 ],
		[ 'directory', 'cache', null, null, null, 1, 0, 0 ],
		[ 'directory', 'public', null, null, null, 1, 0, 0 ],
	],
	'php: directory components'
);
eq( array_column( comp_of( $r, 'other', '' )['findings'] ?? [], 'file' ), [ '.git/y.php', 'node_modules/x.php' ], 'php: code files in node_modules/ and .git/ are checked' );
eq( $r['not_checked'] ?? null, [], 'php: not_checked empty (assets/node_modules/ without code is silent)' );

// ------------------------------------------------------------ other statuses

$nc = out( 'nocode' );
eq( $nc, [ 'v' => 1, 'status' => 'no_code_found', 'site' => 'fixture.test', 'target' => '8.4', 'safe_to_upgrade' => null ], 'nocode: no_code_found document' );
eq( report( 'nocode' ), $nc, 'nocode: report.json equals stdout' );

$bad = out( 'badargs' );
eq( rc( 'badargs' ), 2, 'badargs: exit 2' );
check( 'tool_error' === ( $bad['status'] ?? '' ) && 0 === strpos( $bad['detail'] ?? '', 'bad arguments: ' ), 'badargs: tool_error with detail' );

// ----------------------------------------------------------------- estimate

foreach ( [ 'est' => [ $full, 'full' ], 'est-php' => [ $php, 'php' ] ] as $name => list( $scan, $of ) ) {
	$e = out( $name );
	eq( array_keys( $e ), [ 'v', 'status', 'estimate', 'site', 'target', 'php_files', 'php_bytes', 'components', 'estimated_seconds', 'estimated_seconds_low', 'estimated_seconds_high', 'inputs' ], "$name: keys" );
	eq( [ $e['status'] ?? null, $e['estimate'] ?? null ], [ 'ok', true ], "$name: status ok" );
	eq(
		[ $e['php_files'] ?? null, $e['php_bytes'] ?? null, $e['components'] ?? null ],
		[ $scan['files_checked'] + $scan['files_not_checked'], $scan['php_bytes'], $scan['components_checked'] ],
		"$name: counts equal the $of scan"
	);
	$lo = $e['estimated_seconds_low'] ?? 0;
	$mid = $e['estimated_seconds'] ?? 0;
	$hi = $e['estimated_seconds_high'] ?? 0;
	check( $lo > 0 && $lo <= $mid && $mid <= $hi, "$name: times positive and ordered ($lo <= $mid <= $hi)" );
	$in = $e['inputs'] ?? [];
	check( ( $in['calibration_bytes'] ?? 0 ) > 500000 && ( $in['bytes_per_second'] ?? 0 ) > 0 && ( $in['cpus'] ?? 0 ) == 1 && isset( $in['load_average_1m'], $in['batches'], $in['seconds_per_batch'], $in['low_factor'], $in['high_factor'] ), "$name: inputs" );
}
tool_error( 'est-timeout', 'timed out after 1 s', 1, false );
tool_error( 'badver', 'bad arguments: version must look like 8.4', 2, false );
eq( out( 'est-nocode' ), [ 'v' => 1, 'status' => 'no_code_found', 'estimate' => true, 'site' => 'fixture.test', 'target' => '8.4', 'safe_to_upgrade' => null ], 'est-nocode: no_code_found' );
// ------------------------------------------------- changes, access, limits

foreach ( [ 'switch', 'changed' ] as $name ) {
	eq( trim( raw( "$name.sync" ) ), 'ok', "$name: the change lands after the listing, before the next file" );
}
tool_error( 'switch', 'the site code changed during the scan', 1 );
$ch = out( 'changed' );
eq( [ $ch['status'] ?? null, field( $ch, 'safe_to_upgrade' ), $ch['errors'] ?? null, $ch['files_checked'] ?? null, $ch['files_not_checked'] ?? null ], [ 'ok', false, 1, 2, 0 ], 'changed: a file that grew since the listing is checked as it is now' );
eq( [ $ch['php_bytes'] ?? null, array_column( comp_of( report( 'changed' ), 'plugin', 'p' )['findings'] ?? [], 'file' ) ], [ (int) trim( raw( 'changed.bytes' ) ), [ 'z.php' ] ], 'changed: its new size and content count' );

$rl = out( 'rootlock' );
eq( [ $rl['status'] ?? null, field( $rl, 'safe_to_upgrade' ), $rl['files_not_checked'] ?? null ], [ 'ok', null, 1 ], 'rootlock: an unreachable root is not no_code_found' );
eq( report( 'rootlock' )['not_checked'] ?? null, [ [ 'type' => 'other', 'slug' => '', 'branch' => null, 'file' => './', 'reason' => 'unreadable' ] ], 'rootlock: the root is unreadable' );
$e = out( 'est-rootlock' );
eq( [ $e['status'] ?? null, $e['php_files'] ?? null ], [ 'ok', 1 ], 'est-rootlock: counted like the scan' );

tool_error( 'reportdir', 'could not write the report', 1, false );
eq( trim( raw( 'reportdir.outdir' ) ), './report.json', 'reportdir: no report.json.tmp left behind' );

$bm  = out( 'bigmsg' );
$msg = '';
foreach ( comp_of( report( 'bigmsg' ), 'plugin', 'p' )['findings'] ?? [] as $f ) {
	if ( 'PHPCompatibility.Variables.ForbiddenGlobalVariableVariable.Found' === $f['source'] ) {
		$msg = $f['message'];
	}
}
eq( [ $bm['status'] ?? null, field( $bm, 'safe_to_upgrade' ), $bm['files_not_checked'] ?? null ], [ 'ok', false, 0 ], 'bigmsg: a finding quoting more than 1 MiB of code is reported' );
check( 0 === strpos( $msg, 'Global with variable variables' ) && 65539 === strlen( $msg ) && '…' === substr( $msg, -3 ), 'bigmsg: message cut to 64 KiB (' . strlen( $msg ) . ' bytes)' );

tool_error( 'est-inf', 'bad arguments: COMPAT_SECONDS_PER_BATCH must be a finite', 2, false );
tool_error( 'est-factors', 'bad arguments: COMPAT_LOW_FACTOR must be at most 1', 2, false );

// ------------------------------------------------------------------ scope

$ws = out( 'wpscope' );
$wr = report( 'wpscope' );
eq( [ $ws['status'] ?? null, field( $ws, 'safe_to_upgrade' ), $ws['errors'] ?? null, $ws['files_checked'] ?? null, $ws['files_not_checked'] ?? null ], [ 'ok', false, 13, 13, 3 ], 'wpscope: everything but core checked (the root\'s own index.php too)' );
eq(
	comp_rows( $wr ),
	[
		[ 'directory', 'htdocs', null, null, null, 2, 2, 0 ],
		[ 'directory', 'htdocs/forum', null, null, null, 2, 2, 0 ],
		[ 'other', '', 'htdocs/content', null, null, 2, 2, 0 ],
		[ 'plugin', 'plug-in', null, 'Plug In', null, 1, 1, 0 ],
		[ 'plugin', 'plug-v', null, 'Plug V', null, 1, 1, 0 ],
		[ 'plugin', 'moved', 'htdocs/content', 'Moved', null, 1, 1, 0 ],
		[ 'theme', 'theme-in', null, 'Theme In', null, 1, 1, 0 ],
		[ 'mu-plugin', 'mu-plugins', null, null, null, 1, 1, 0 ],
		[ 'directory', 'htdocs/shared', null, null, null, 1, 1, 0 ],
		[ 'directory', 'htdocs/wp', null, null, null, 1, 1, 0 ],
	],
	'wpscope: links into the WordPress dir keep their component; a content dir beside wp-content is a branch; the rest are directories; core never'
);
eq( $wr['not_checked'] ?? null, [ nc( 'other', '', null, 'core-version.php', 'unreadable' ), nc( 'other', '', null, 'inc/', 'unreadable' ), [ 'type' => 'directory', 'slug' => 'htdocs/wp', 'branch' => null, 'file' => './', 'reason' => 'nested_wordpress' ] ], 'wpscope: links into the root\'s core are entries; the subdirectory install\'s core is reported, not skipped silently' );
$ff = [];
foreach ( $wr['components'] ?? [] as $c ) {
	foreach ( $c['findings'] as $f ) {
		$ff[] = $c['slug'] . ':' . $f['file'];
	}
}
sort( $ff );
eq( $ff, [ ':object-cache.php', ':uploads/up.php', 'htdocs/forum:inc/version.php', 'htdocs/forum:index.php', 'htdocs/shared:loose.php', 'htdocs/wp:wp-content/plugins/stock/stock.php', 'htdocs:custom-api.php', 'htdocs:index.php', 'moved:moved.php', 'mu-plugins:mu-link.php', 'plug-in:plug-in.php', 'plug-v:plug-v.php', 'theme-in:functions.php' ], 'wpscope: finding files (core and links to core or into it absent; the moved content dir\'s uploads/ checked; a version.php outside core checked)' );
$e = out( 'est-wpscope' );
eq( [ $e['php_files'] ?? null, $e['php_bytes'] ?? null, $e['components'] ?? null ], [ 16, $ws['php_bytes'] ?? null, 10 ], 'est-wpscope: counts equal the scan' );

$wm = out( 'wpmoved' );
eq( [ $wm['status'] ?? null, field( $wm, 'safe_to_upgrade' ), $wm['errors'] ?? null, $wm['files_checked'] ?? null ], [ 'ok', false, 1, 2 ], 'wpmoved: no wp-content, a moved content dir is still checked' );
eq( comp_rows( report( 'wpmoved' ) ), [ [ 'plugin', 'p', 'htdocs/app', 'P', null, 1, 1, 0 ], [ 'other', 'wp-config.php', null, null, null, 1, 0, 0 ] ], 'wpmoved: plugin of branch htdocs/app, and wp-config.php' );

foreach ( [ 'wplink-dangling', 'wplink-out', 'phplink-dangling' ] as $name ) {
	$d = out( $name );
	eq( [ $d['status'] ?? null, field( $d, 'safe_to_upgrade' ), $d['files_checked'] ?? null, $d['files_not_checked'] ?? null ], [ 'ok', null, 0, 1 ], "$name: a root behind a bad link is not no_code_found" );
	eq( report( $name )['not_checked'] ?? null, [ [ 'type' => 'other', 'slug' => '', 'branch' => null, 'file' => './', 'reason' => 'unreadable' ] ], "$name: the root is unreadable" );
}

$pb = out( 'phpbeside' );
eq( [ $pb['status'] ?? null, field( $pb, 'safe_to_upgrade' ), $pb['errors'] ?? null, $pb['files_checked'] ?? null, $pb['files_not_checked'] ?? null ], [ 'ok', false, 4, 5, 0 ], 'phpbeside: code beside htdocs checked, and the code-named files of the home dirs' );
eq( report( 'phpbeside' )['not_checked'] ?? null, [], 'phpbeside: home dirs holding code are no entries' );
eq( finding_files( report( 'phpbeside' ) ), [ 'directory:../app::src/boot.php', 'directory:..::.composer/vendor/x/y.php', 'directory:..::.wp-cli/packages/z.php', 'directory:..::lib.php' ], 'phpbeside: findings in the home dirs count' );
eq(
	comp_rows( report( 'phpbeside' ) ),
	[
		[ 'directory', '..', null, null, null, 3, 3, 0 ],
		[ 'directory', '../app', null, null, null, 1, 1, 0 ],
		[ 'other', '', null, null, null, 1, 0, 0 ],
	],
	'phpbeside: components (htdocs -> app/public listed once, as htdocs)'
);
eq( array_column( comp_of( report( 'phpbeside' ), 'directory', '../app' )['findings'] ?? [], 'file' ), [ 'src/boot.php' ], 'phpbeside: ../app finding path' );
$pd = out( 'phpdeep' );
eq( [ $pd['status'] ?? null, field( $pd, 'safe_to_upgrade' ), $pd['errors'] ?? null, $pd['files_checked'] ?? null ], [ 'ok', false, 2, 3 ], 'phpdeep: code two levels above the public dir checked' );
eq( array_column( comp_of( report( 'phpdeep' ), 'directory', '../project' )['findings'] ?? [], 'file' ), [ 'app/src/boot.php', 'lib/x.php' ], 'phpdeep: ../project findings (public listed once, as htdocs)' );
$e = out( 'est-phpbeside' );
eq( [ $e['php_files'] ?? null, $e['components'] ?? null ], [ 5, 3 ], 'est-phpbeside: counts equal the scan' );

$bd = out( 'bedrock' );
$bf = [];
foreach ( report( 'bedrock' )['components'] ?? [] as $c ) {
	foreach ( $c['findings'] as $f ) {
		$bf[] = $c['type'] . ':' . $c['slug'] . ':' . $f['file'];
	}
}
sort( $bf );
eq( [ $bd['status'] ?? null, field( $bd, 'safe_to_upgrade' ), $bd['errors'] ?? null ], [ 'ok', false, 5 ], 'bedrock: verdict and errors (web/app is inside a directory component, so its uploads/ is walked)' );
eq( $bf, [ 'directory:htdocs/config:application.php', 'directory:htdocs/vendor:acme/lib/Lib.php', 'directory:htdocs/web:app/mu-plugins/m.php', 'directory:htdocs/web:app/plugins/p/p.php', 'directory:htdocs/web:app/uploads/u.php' ], 'bedrock: config/, vendor/ and web/app checked, web/wp core not' );
eq( report( 'bedrock' )['not_checked'] ?? null, [ [ 'type' => 'directory', 'slug' => 'htdocs/web/wp', 'branch' => null, 'file' => './', 'reason' => 'nested_wordpress' ] ], 'bedrock: web/wp is not the scanned WordPress root, so its core is reported' );

eq( trim( (string) file_get_contents( "$dir/tree" ) ), 'unchanged', 'fixture tree unchanged by scans and estimates' );
eq( trim( (string) file_get_contents( "$dir/mount-rw" ) ), 'writable', 'mount probe: uid 33 can write the probe dir through a writable mount' );
eq( trim( (string) file_get_contents( "$dir/mount-ro" ) ), 'readonly', 'code mount is read-only inside the container' );

// ------------------------------------------------------ code file extensions

$ext = out( 'ext' );
$r   = report( 'ext' );
eq( [ $ext['status'] ?? null, field( $ext, 'safe_to_upgrade' ), $ext['errors'] ?? null, $ext['warnings'] ?? null, $ext['files_checked'] ?? null, $ext['files_not_checked'] ?? null, $ext['components_checked'] ?? null, $ext['components_with_errors'] ?? null ], [ 'ok', false, 15, 0, 19, 4, 4, 3 ], 'ext: verdict and counts' );
eq(
	comp_rows( $r ),
	[
		[ 'plugin', 'ext', null, 'Ext', null, 12, 11, 0 ],
		[ 'plugin', 'dedup', null, 'Dedup', null, 3, 2, 0 ],
		[ 'other', '', null, null, null, 2, 2, 0 ],
		[ 'plugin', 'hdr', null, 'hdr', null, 2, 0, 0 ],
	],
	'ext: components (no single-file plugin from legacy.inc or Loose.PHP; hdr has no lowercase .php header file)'
);
eq(
	array_column( comp_of( $r, 'plugin', 'ext' )['findings'] ?? [], 'file' ),
	[ 'Mixed.Inc', 'UPPER.PHP', 'x.engine', 'x.inc', 'x.install', 'x.module', 'x.php5', 'x.php7', 'x.phps', 'x.phtml', 'x.theme' ],
	'ext: one finding per code extension, in any case, under the real name; x.phps starts with <?php, so it is PHP too; readme.txt and x.js are never sniffed'
);
eq( array_unique( array_column( comp_of( $r, 'plugin', 'ext' )['findings'] ?? [], 'source' ) ), [ 'PHPCompatibility.FunctionUse.RemovedFunctions.eachDeprecatedRemoved' ], 'ext: canaries are the each() error' );
eq( array_column( comp_of( $r, 'other', '' )['findings'] ?? [], 'file' ), [ 'plugins/Loose.PHP', 'plugins/legacy.inc' ], 'ext: loose non-.php code files in plugins/ belong to other' );
eq( array_column( comp_of( $r, 'plugin', 'dedup' )['findings'] ?? [], 'file' ), [ 'a.inc', 'b.inc' ], 'ext: z.php -> a.inc checked once as a.inc; b.inc -> data.txt checked under the link name' );
eq(
	$r['not_checked'] ?? null,
	[
		[ 'type' => 'plugin', 'slug' => 'ext', 'branch' => null, 'file' => 'gone.inc', 'reason' => 'unreadable' ],
		[ 'type' => 'plugin', 'slug' => 'ext', 'branch' => null, 'file' => 'gone.old', 'reason' => 'unreadable' ],
		[ 'type' => 'other', 'slug' => '', 'branch' => null, 'file' => 'plugins/gone.inc', 'reason' => 'unreadable' ],
		[ 'type' => 'other', 'slug' => '', 'branch' => null, 'file' => 'themes/gone.inc', 'reason' => 'unreadable' ],
	],
	'ext: dangling code-named links, and one with a backup name, are unreadable, in plugins/ and themes/ under other'
);
$err = raw( 'ext.stderr' );
preg_match_all( '/\] single (\S+) at /', $err, $m );
$singles = $m[1];
sort( $singles );
check( 1 === preg_match_all( '/\] batch 13 files rc=/', $err ), 'ext: one batch of 13 files (lowercase extensions)' );
eq(
	$singles,
	array_map(
		static function ( $f ) { return "/var/www/htdocs/wp-content/plugins/$f"; },
		[ 'Loose.PHP', 'dedup/b.inc', 'ext/Mixed.Inc', 'ext/UPPER.PHP', 'ext/x.phps', 'hdr/MAIN.PHP' ]
	),
	'ext: names PHPCS filters by extension go through STDIN, once each'
);
$e = out( 'est-ext' );
eq( [ $e['php_files'] ?? null, $e['php_bytes'] ?? null, $e['components'] ?? null ], [ $ext['files_checked'] + $ext['files_not_checked'], $ext['php_bytes'] ?? null, $ext['components_checked'] ?? null ], 'est-ext: counts equal the scan' );

$ep = out( 'ext-php' );
$r  = report( 'ext-php' );
eq( [ $ep['status'] ?? null, field( $ep, 'safe_to_upgrade' ), $ep['errors'] ?? null, $ep['files_checked'] ?? null, $ep['files_not_checked'] ?? null ], [ 'ok', false, 2, 2, 1 ], 'ext-php: code only in non-.php names is not no_code_found' );
eq(
	comp_rows( $r ),
	[
		[ 'directory', 'app', null, null, null, 1, 1, 0 ],
		[ 'other', '', null, null, null, 1, 1, 0 ],
	],
	'ext-php: components'
);
eq( [ array_column( comp_of( $r, 'directory', 'app' )['findings'] ?? [], 'file' ), array_column( comp_of( $r, 'other', '' )['findings'] ?? [], 'file' ) ], [ [ 'Y.PHTML' ], [ 'x.inc' ] ], 'ext-php: findings by file (readme.txt is never sniffed)' );
eq( $r['not_checked'] ?? null, [ [ 'type' => 'other', 'slug' => '', 'branch' => null, 'file' => 'gone.inc', 'reason' => 'unreadable' ] ], 'ext-php: a dangling .inc link in the root is other, not a directory' );
$e = out( 'est-ext-php' );
eq( [ $e['php_files'] ?? null, $e['php_bytes'] ?? null, $e['components'] ?? null ], [ $ep['files_checked'] + $ep['files_not_checked'], $ep['php_bytes'] ?? null, $ep['components_checked'] ?? null ], 'est-ext-php: counts equal the scan' );

// ---------------------------------------------------------- more edge cases

eq( trim( raw( 'changed-gone.sync' ) ), 'ok', 'changed-gone: the change lands after the listing, before the next file' );
$cg = out( 'changed-gone' );
eq( [ $cg['status'] ?? null, field( $cg, 'safe_to_upgrade' ), $cg['files_checked'] ?? null ], [ 'ok', true, 1 ], 'changed-gone: the remaining file checked' );
eq( report( 'changed-gone' )['not_checked'] ?? null, [], 'changed-gone: a file deleted since the listing can\'t run, so it is dropped' );

$sl = out( 'slashes' );
$r  = report( 'slashes' );
eq( without_duration( $sl ), without_duration( $full ), 'slashes: a path with repeated slashes scans like the plain one' );
eq( [ $r['components'] ?? null, $r['not_checked'] ?? null ], [ $rep['components'] ?? [], $rep['not_checked'] ?? [] ], 'slashes: same findings and not_checked' );
$prs = out( 'php-rel-slashes' );
eq( [ without_duration( $prs ), report( 'php-rel-slashes' )['components'] ?? null ], [ without_duration( $pr ), report( 'php-rel' )['components'] ?? [] ], 'php-rel-slashes: the release layout is found through repeated slashes' );
$es = out( 'est-slashes' );
$e  = out( 'est' );
eq( [ $es['status'] ?? null, $es['php_files'] ?? null, $es['php_bytes'] ?? null, $es['components'] ?? null ], [ 'ok', $e['php_files'] ?? 0, $e['php_bytes'] ?? 0, $e['components'] ?? 0 ], 'est-slashes: counts equal the plain path' );
tool_error( 'badargs-dotdot', 'bad arguments: path must be', 2, false );
tool_error( 'badargs-slashdot', 'bad arguments: path must be', 2, false );

$tb = out( 'tempbackup' );
eq( [ $tb['status'] ?? null, field( $tb, 'safe_to_upgrade' ), $tb['errors'] ?? null, $tb['files_checked'] ?? null ], [ 'ok', false, 2, 3 ], "tempbackup: WordPress' rollback copies in upgrade-temp-backup/ are checked (not walked as plugins)" );
eq( comp_rows( report( 'tempbackup' ) ), [ [ 'other', '', null, null, null, 2, 2, 0 ], [ 'plugin', 'p', null, 'P', null, 1, 0, 0 ] ], 'tempbackup: the copies belong to other' );
eq( report( 'tempbackup' )['not_checked'] ?? null, [], 'tempbackup: not_checked empty' );

// ------------------------------------------------------ nothing skipped silently

function nc( string $type, string $slug, ?string $branch, string $file, string $reason ): array {
	return [ 'type' => $type, 'slug' => $slug, 'branch' => $branch, 'file' => $file, 'reason' => $reason ];
}

/** "type:slug:branch:file" of every finding. */
function finding_files( array $report ): array {
	$out = [];
	foreach ( $report['components'] ?? [] as $c ) {
		foreach ( $c['findings'] as $f ) {
			$out[] = $c['type'] . ':' . $c['slug'] . ':' . $c['branch'] . ':' . $f['file'];
		}
	}
	sort( $out );
	return $out;
}

$wf = out( 'wordfence' );
eq( [ $wf['status'] ?? null, field( $wf, 'safe_to_upgrade' ), $wf['errors'] ?? null, $wf['files_checked'] ?? null, $wf['files_not_checked'] ?? null ], [ 'ok', true, 0, 17, 0 ], 'wordfence: Wordfence\'s wflogs/*.php (exit; __halt_compiler(); data, and a compiled rules.php) are checked and clean, in uploads/ and in wp-content' );
eq( report( 'wordfence' )['not_checked'] ?? null, [], 'wordfence: not_checked empty' );

$sd = out( 'skipdirs' );
eq( [ $sd['status'] ?? null, field( $sd, 'safe_to_upgrade' ), $sd['errors'] ?? null, $sd['files_checked'] ?? null, $sd['files_not_checked'] ?? null ], [ 'ok', false, 7, 17, 1 ], 'skipdirs: code files in skipped dirs are checked' );
eq(
	finding_files( report( 'skipdirs' ) ),
	[ 'directory:htdocs::node_modules/x.php', 'other:::.git/hooks/h.php', 'other:::cache/object/c.php', 'other:::node_modules/n.php', 'other:::uploads/2026/11/deep/shell.PHP', 'plugin:p::.git/y.php', 'plugin:p::node_modules/pkg/x.php' ],
	'skipdirs: findings in uploads/ (any case, any depth), cache/, node_modules/ and .git/ at every level (not in non-code names there)'
);
eq( comp_of( report( 'skipdirs' ), 'other', '' )['files'] ?? null, 13, 'skipdirs: other has wflogs (8), upgrade-temp-backup, uploads, cache, node_modules and .git files' );
eq(
	report( 'skipdirs' )['not_checked'] ?? null,
	[ nc( 'directory', 'htdocs', null, '.git/', 'unreadable' ) ],
	'skipdirs: a dangling skipped name is unreadable'
);
eq( report( 'skipdirs' )['phars'] ?? null, [ '/var/www/htdocs/wp-content/upgrade/pkg.phar' ], 'skipdirs: a phar in a skipped dir is found' );
$e = out( 'est-skipdirs' );
eq( [ $e['php_files'] ?? null, $e['php_bytes'] ?? null, $e['components'] ?? null ], [ 18, $sd['php_bytes'] ?? null, 3 ], 'est-skipdirs: counts equal the scan' );
$sp = out( 'skipdirs-php' );
eq( [ $sp['status'] ?? null, field( $sp, 'safe_to_upgrade' ), $sp['errors'] ?? null, $sp['files_checked'] ?? null, $sp['files_not_checked'] ?? null ], [ 'ok', false, 7, 17, 2 ], 'skipdirs-php: a php site walks uploads/ and cache/ whole (a .txt is never sniffed); node_modules/ and .git/ code files checked' );
eq( report( 'skipdirs-php' )['not_checked'] ?? null, [ nc( 'other', '', null, '.git/', 'unreadable' ), nc( 'directory', 'htdocs', null, './', 'nested_wordpress' ) ], 'skipdirs-php: not_checked; the WordPress core in htdocs is judged as an install, not scanned' );

$cl = out( 'contentlike' );
eq( [ $cl['status'] ?? null, field( $cl, 'safe_to_upgrade' ), $cl['errors'] ?? null, $cl['files_checked'] ?? null, $cl['files_not_checked'] ?? null ], [ 'ok', false, 2, 3, 0 ], 'contentlike: verdict and counts' );
eq( finding_files( report( 'contentlike' ) ), [ 'other::htdocs/tools:cache/shell.php', 'other::main:uploads/u.php' ], 'contentlike: cache/ and uploads/ of a content root other than wp-content are checked' );

$pn = out( 'pluginnm' );
eq( [ $pn['status'] ?? null, field( $pn, 'safe_to_upgrade' ), $pn['errors'] ?? null, $pn['files_checked'] ?? null ], [ 'ok', false, 3, 3 ], 'pluginnm: verdict and counts' );
eq(
	comp_rows( report( 'pluginnm' ) ),
	[
		[ 'plugin', '.git', null, '.git', null, 1, 1, 0 ],
		[ 'plugin', 'node_modules', null, 'Evil', null, 1, 1, 0 ],
		[ 'theme', 'node_modules', null, 'NM', null, 1, 1, 0 ],
	],
	'pluginnm: plugin and theme dirs named node_modules or .git are scanned'
);

$ln = out( 'l10n' );
eq( [ $ln['status'] ?? null, field( $ln, 'safe_to_upgrade' ), $ln['errors'] ?? null, $ln['files_checked'] ?? null, $ln['files_not_checked'] ?? null ], [ 'ok', false, 1, 2, 0 ], 'l10n: languages/ is checked' );
eq( finding_files( report( 'l10n' ) ), [ 'other:::languages/plugins/x-de_DE.l10n.php' ], 'l10n: a .l10n.php file is checked, as part of other (languages/ is not a content root)' );

$sn = out( 'sniff' );
$r  = report( 'sniff' );
eq( [ $sn['status'] ?? null, field( $sn, 'safe_to_upgrade' ), $sn['errors'] ?? null, $sn['files_checked'] ?? null, $sn['files_not_checked'] ?? null ], [ 'ok', false, 4, 7, 2 ], 'sniff: verdict and counts (README.md, notes.txt, app.js, app.ts, style.css, data.json, big.txt and logo.png are not sniffed or not PHP)' );
eq( array_column( array_filter( comp_of( $r, 'plugin', 'p' )['findings'] ?? [], static function ( $f ) { return 'WARNING' === $f['type']; } ), 'file' ), [ 'views/warn.html' ], 'sniff: a later tag with warnings only is checked and its warnings kept' );
eq( finding_files( $r ), [ 'plugin:p::a-tpl.txt', 'plugin:p::bin/tool', 'plugin:p::views/admin.tpl', 'plugin:p::views/bom.html', 'plugin:p::views/warn.html' ], 'sniff: files starting with <?php or <?= (after a #! line or a BOM) are PHP; so is a link to a .php file (checked under the link name); warn.html has a warning' );
eq(
	$r['not_checked'] ?? null,
	[
		nc( 'plugin', 'p', null, 'gone.phar', 'unreadable' ),
		nc( 'plugin', 'p', null, 'views/page.html', 'php_tag' ),
	],
	'sniff: a dangling .phar link, and text with a later PHP tag that has errors'
);
eq( [ $r['phars'] ?? null, field( $r, 'phar_named_by' ) ], [ [ '/var/www/htdocs/wp-content/plugins/p/a-lib.php', '/var/www/htdocs/wp-content/plugins/p/lib.phar.tar.gz' ], null ], 'sniff: phars no code names are information: one first reached through a .php link (listed once, as the link), a .phar.tar.gz' );
check( in_array( '/var/www/htdocs/wp-content/plugins/p/big-mixed.tpl', json_decode( raw( 'sniff.manifest.json' ), true )['checked'] ?? [], true ), 'sniff: a mixed file over 1 MiB is scanned' );
$e = out( 'est-sniff' );
eq( [ $e['php_files'] ?? null, $e['components'] ?? null, $e['inputs']['stdin_files'] ?? null ], [ 9, 1, 6 ], 'est-sniff: counts equal the scan; 6 files go through STDIN' );
$sp = out( 'sniff-php' );
eq( [ $sp['status'] ?? null, field( $sp, 'safe_to_upgrade' ), $sp['errors'] ?? null, $sp['files_checked'] ?? null, $sp['files_not_checked'] ?? null ], [ 'ok', false, 4, 7, 2 ], 'sniff-php: the same on a php site' );
eq( array_column( report( 'sniff-php' )['not_checked'] ?? [], 'reason' ), [ 'unreadable', 'php_tag' ], 'sniff-php: same not_checked reasons' );

$ne = out( 'nested' );
$r  = report( 'nested' );
eq( [ $ne['status'] ?? null, field( $ne, 'safe_to_upgrade' ), $ne['errors'] ?? null, $ne['files_checked'] ?? null, $ne['files_not_checked'] ?? null ], [ 'ok', false, 5, 5, 2 ], 'nested: verdict and counts' );
eq( finding_files( $r ), [ 'directory:htdocs/old::custom.php', 'directory:htdocs/old::index.php', 'directory:htdocs::index.php', 'directory:htdocs::wp-custom.php', 'plugin:fakecore::index.php' ], 'nested: non-core files and every index.php are checked; core (wp-settings.php, wp-includes/) is not' );
eq(
	$r['not_checked'] ?? null,
	[
		nc( 'directory', 'htdocs/old', null, './', 'nested_wordpress' ),
		nc( 'directory', 'htdocs/wp-content/plugins/fakecore', null, './', 'nested_wordpress' ),
	],
	'nested: another install\'s core (also inside a plugin, also behind a link) is reported once per install'
);
$e = out( 'est-nested' );
eq( [ $e['php_files'] ?? null, $e['components'] ?? null ], [ 7, 3 ], 'est-nested: counts equal the scan' );

$hg = out( 'hang' );
$r  = report( 'hang' );
eq( [ $hg['status'] ?? null, field( $hg, 'safe_to_upgrade' ) ], [ 'ok', null ], 'hang: sniffed files that outrun their cap don\'t stop the scan' );
check( in_array( nc( 'plugin', 'p', null, 'views/slow.tpl', 'timeout' ), $r['not_checked'] ?? [], true ), 'hang: slow.tpl is a timeout entry after COMPAT_SNIFFED_TIMEOUT' );
// hang.tpl hangs this PHPCompatibility; a release that fixes that may check it or make it php_tag instead.
$others = array_values( array_filter( $r['not_checked'] ?? [], static function ( $n ) { return 'views/slow.tpl' !== $n['file']; } ) );
check( [] === $others || ( 1 === count( $others ) && 'views/hang.tpl' === $others[0]['file'] && in_array( $others[0]['reason'], [ 'timeout', 'php_tag' ], true ) ), 'hang: hang.tpl is timeout, php_tag or checked (' . json_encode( $others ) . ')' );
check( ( $hg['duration_s'] ?? 99 ) < 30, 'hang: the scan ends soon after the caps (' . ( $hg['duration_s'] ?? '?' ) . ' s)' );

foreach ( [ 'cache' => 2506, 'cache50k' => 50006 ] as $name => $n ) {
	$ca = out( $name );
	eq( [ $ca['status'] ?? null, field( $ca, 'safe_to_upgrade' ), $ca['errors'] ?? null, $ca['files_checked'] ?? null, $ca['files_not_checked'] ?? null ], [ 'ok', false, 1, $n, 0 ], "$name: W3TC, WP Super Cache and Wordfence-style data files, a 9 MB one too, are checked without PHPCS; Docket Cache code is scanned" );
	eq( finding_files( report( $name ) ), [ 'other:::cache/object/tail.php' ], "$name: a data header followed by another open tag is scanned" );
	check( ( $ca['duration_s'] ?? 999 ) < 120, "$name: done in " . ( $ca['duration_s'] ?? '?' ) . ' s' );
}
check( 1 === preg_match_all( '/\] batch 3 files rc=/', raw( 'cache.stderr' ) ), 'cache: one PHPCS batch, of p.php, the Docket Cache file and tail.php (data-only files, huge.php too, take no run)' );
$e = out( 'est-cache' );
eq( [ $e['php_files'] ?? null, $e['components'] ?? null ], [ 2506, 2 ], 'est-cache: counts equal the scan' );

$el = tool_error( 'est-listing', 'too large to estimate in 1 s: ', 1, false );
eq( array_keys( $el ), [ 'v', 'status', 'estimate', 'site', 'target', 'safe_to_upgrade', 'detail' ], 'est-listing: reduced keys' );
check( 1 === preg_match( '/^too large to estimate in 1 s: (\d+) PHP files listed before the time ran out; run the check itself, without --estimate\z/', $el['detail'] ?? '', $m ) && (int) $m[1] < 20000, 'est-listing: detail counts the files listed so far (' . ( $el['detail'] ?? '' ) . ')' );

// STDIN: a first line starting `phpcs_input_file:` is checked at its own line numbers (LF, CRLF, CR), also in a name
// with a newline and in a sniffed file; names that differ only in control characters stay two entries.
$sd = out( 'stdin' );
$r  = report( 'stdin' );
eq( [ $sd['status'] ?? null, field( $sd, 'safe_to_upgrade' ), $sd['errors'] ?? null, $sd['files_checked'] ?? null, $sd['files_not_checked'] ?? null ], [ 'ok', false, 8, 6, 3 ], 'stdin: verdict and counts' );
$rows = [];
foreach ( comp_of( $r, 'plugin', 's' )['findings'] ?? [] as $f ) {
	$rows[] = $f['file'] . ':' . $f['line'] . ':' . substr( strrchr( $f['source'], '.' ), 1 );
}
eq(
	$rows,
	[
		'X.PHP:1:create_functionDeprecatedRemoved', 'X.PHP:2:eachDeprecatedRemoved',
		'cr.PHP:1:create_functionDeprecatedRemoved', 'cr.PHP:2:eachDeprecatedRemoved',
		'crlf.PHP:1:create_functionDeprecatedRemoved', 'crlf.PHP:2:eachDeprecatedRemoved',
		"new\u{FFFD}line.php:1:create_functionDeprecatedRemoved", "new\u{FFFD}line.php:2:eachDeprecatedRemoved",
	],
	'stdin: findings on line 1 and 2 of each file read through STDIN'
);
eq( $r['not_checked'] ?? null, [ nc( 'plugin', 's', null, 'bin/tool', 'php_tag' ), nc( 'plugin', 's', null, "t\u{FFFD}.tpl", 'php_tag' ), nc( 'plugin', 's', null, "t\u{FFFD}.tpl", 'php_tag' ) ], 'stdin: the sniffed file with code on its first line is php_tag; the twins are two entries' );
$m = json_decode( raw( 'stdin.manifest.json' ), true );
$p = '/var/www/htdocs/wp-content/plugins/';
eq( $m['not_checked'] ?? null, [ $p . 's/bin/tool', $p . "s/t\x01.tpl", $p . "s/t\x02.tpl" ], 'stdin: manifest not_checked by real path, control characters kept' );
check( in_array( 'b64:' . base64_encode( $p . "\xff/node_modules/" ), $m['sniff']['skipped_dirs'] ?? [], true ), 'stdin: a skipped dir under a non-UTF-8 name is b64: in sniff.skipped_dirs' );

// Php sites: dot dirs of /var/www (the www-data home) are one entry when they hold code; one holding the public dir is walked.
$pd = out( 'phpdot' );
eq( [ $pd['status'] ?? null, field( $pd, 'safe_to_upgrade' ), $pd['errors'] ?? null, $pd['files_checked'] ?? null, $pd['files_not_checked'] ?? null ], [ 'ok', false, 3, 4, 0 ], 'phpdot: verdict and counts' );
eq( finding_files( report( 'phpdot' ) ), [ 'directory:../.release::lib/helper.php', 'directory:..::.user.php', 'directory:..::.wp-cli/packages/vendor/v/v.php' ], 'phpdot: code beside the public dir in .release, a dot file and a code file in the home are checked; the home\'s extension-less script isn\'t sniffed' );
$home = [ '/var/www/.cache/', '/var/www/.composer/', '/var/www/.npm/', '/var/www/.wp-cli/' ];
$m    = json_decode( raw( 'phpdot.manifest.json' ), true );
eq( [ $m['sniff']['skipped_dirs'] ?? null, $m['not_checked'] ?? null ], [ $home, [] ], 'phpdot: the home dirs are searched by name only' );
$pr = out( 'phpdot-root' );
eq( [ $pr['status'] ?? null, field( $pr, 'safe_to_upgrade' ), $pr['files_checked'] ?? null, $pr['files_not_checked'] ?? null ], [ 'ok', true, 1, 0 ], 'phpdot-root: htdocs -> .release is scanned as the root; tool caches give no entry' );
eq( json_decode( raw( 'phpdot-root.manifest.json' ), true )['sniff']['skipped_dirs'] ?? null, $home, 'phpdot-root: the home dirs are searched by name only' );

// A directory uid 33 can list but not search is one entry, also inside a skipped dir.
$ut = out( 'untrav' );
eq( [ $ut['status'] ?? null, field( $ut, 'safe_to_upgrade' ), $ut['files_checked'] ?? null, $ut['files_not_checked'] ?? null ], [ 'ok', null, 1, 2 ], 'untrav: verdict and counts' );
eq( report( 'untrav' )['not_checked'] ?? null, [ nc( 'plugin', 'lk', null, 'locked/', 'unreadable' ), nc( 'other', '', null, 'uploads/locked/', 'unreadable' ) ], 'untrav: unsearchable dirs are directory entries' );
eq( json_decode( raw( 'untrav.manifest.json' ), true )['not_checked'] ?? null, [ '/var/www/htdocs/wp-content/plugins/lk/locked/', '/var/www/htdocs/wp-content/uploads/locked/' ], 'untrav: manifest directory entries end with /' );

// 20,000 not_checked entries in 10M of entrypoint memory: the manifest keeps no set of them.
$pf = out( 'pharflood' );
eq( [ $pf['status'] ?? null, $pf['files_not_checked'] ?? null ], [ 'ok', 20000 ], 'pharflood: many not_checked entries in little memory' );
$pi = out( 'pharflood-info' );
eq( [ $pi['status'] ?? null, field( $pi, 'safe_to_upgrade' ), $pi['files_not_checked'] ?? null, count( report( 'pharflood-info' )['phars'] ?? [] ) ], [ 'ok', true, 0, 20000 ], 'pharflood-info: many phars kept as information in little memory' );

// ----------------------------------------------------------- file manifest

$bk = out( 'bak' );
eq( [ $bk['status'] ?? null, field( $bk, 'safe_to_upgrade' ), $bk['errors'] ?? null, $bk['files_checked'] ?? null, $bk['files_not_checked'] ?? null ], [ 'ok', true, 0, 2, 0 ], 'bak: backup-named files (bak, orig, SAVE, sql) aren\'t read, also one wp-config.php requires' );
eq( json_decode( raw( 'bak.manifest.json' ), true )['checked'] ?? null, [ '/var/www/htdocs/wp-config.php', '/var/www/htdocs/wp-content/themes/t/functions.php' ], 'bak: only the code files checked' );
eq( [ out( 'nomanifest' )['status'] ?? null, trim( raw( 'nomanifest.outdir' ) ) ], [ 'ok', './report.json' ], 'nomanifest: without COMPAT_MANIFEST, /out holds only report.json' );

// r7: a link into an old release or the root's core is an entry by the link's own path (a release pointer beside
// current, and a non-code file link, aren't); php home dot dirs; the per-file cap; the STDIN copy cap.
$ol = out( 'oldlink' );
eq( [ $ol['status'] ?? null, field( $ol, 'safe_to_upgrade' ), $ol['files_checked'] ?? null, $ol['files_not_checked'] ?? null ], [ 'ok', null, 1, 5 ], 'oldlink: links into an old release give no verdict' );
eq( report( 'oldlink' )['not_checked'] ?? null, [ nc( 'directory', 'current', null, 'h.php', 'unreadable' ), nc( 'directory', 'current', null, 'lib/', 'unreadable' ), nc( 'directory', 'current', null, 'vendor/', 'unreadable' ), nc( 'directory', 'shared', null, 'vendor/', 'unreadable' ), nc( 'other', '', null, 'vend/', 'unreadable' ) ], 'oldlink: a file, a relative and an absolute dir link, shared/ and a top-level link into the old release; not previous or notes.txt' );
eq( json_decode( raw( 'oldlink.manifest.json' ), true )['not_checked'] ?? null, [ '/var/www/htdocs/releases/2/h.php', '/var/www/htdocs/releases/2/lib/', '/var/www/htdocs/releases/2/vendor/', '/var/www/htdocs/shared/vendor/', '/var/www/htdocs/vend/' ], 'oldlink: manifest names each link where it is, not its target' );
$cl = out( 'corelink' );
eq( [ $cl['status'] ?? null, field( $cl, 'safe_to_upgrade' ), $cl['files_checked'] ?? null, $cl['files_not_checked'] ?? null ], [ 'ok', null, 2, 11 ], 'corelink: links into core and out of /var/www give no verdict' );
eq( report( 'corelink' )['not_checked'] ?? null, [ nc( 'other', '', null, 'mu-plugins/', 'unreadable' ), nc( 'plugin', 'clean', null, 'boot.php', 'unreadable' ), nc( 'plugin', 'clean', null, 'inc/', 'unreadable' ), nc( 'other', '', null, 'plugins/coreplug/', 'unreadable' ), nc( 'plugin', 'lnk', null, 'lib.d', 'unreadable' ), nc( 'plugin', 'lnk', null, 'part', 'unreadable' ), nc( 'plugin', 'lnk', null, 'shm', 'unreadable' ), nc( 'other', '', null, 'themes/t/', 'unreadable' ), nc( 'other', '', null, 'cache/', 'unreadable' ), nc( 'other', '', null, 'uploads/d/', 'unreadable' ), nc( 'other', '', null, 'uploads/x.php', 'unreadable' ) ], 'corelink: core links (file, dir, plugin dir, theme dir, mu-plugins, a skipped name, links in uploads/) and lib.d/part/shm leaving the mount; not v.txt, out.log, readme.txt, or links to exactly /dev/null, /dev/stdout, /dev/stderr (debug.log, error_log, access, trace)' );
eq( json_decode( raw( 'corelink.manifest.json' ), true )['not_checked'] ?? null, [ '/var/www/htdocs/wp-content/mu-plugins/', '/var/www/htdocs/wp-content/plugins/clean/boot.php', '/var/www/htdocs/wp-content/plugins/clean/inc/', '/var/www/htdocs/wp-content/plugins/coreplug/', '/var/www/htdocs/wp-content/plugins/lnk/lib.d', '/var/www/htdocs/wp-content/plugins/lnk/part', '/var/www/htdocs/wp-content/plugins/lnk/shm', '/var/www/htdocs/wp-content/themes/t/', '/var/www/htdocs/wp-content/cache/', '/var/www/htdocs/wp-content/uploads/d/', '/var/www/htdocs/wp-content/uploads/x.php' ], 'corelink: manifest by link path, never a core path' );
$ph = out( 'phphome' );
eq( [ $ph['status'] ?? null, field( $ph, 'safe_to_upgrade' ), $ph['files_checked'] ?? null, $ph['files_not_checked'] ?? null ], [ 'ok', null, 2, 6 ], 'phphome: verdict and counts' );
eq(
	report( 'phphome' )['not_checked'] ?? null,
	[
		nc( 'directory', '..', null, '.config/chromium/SingletonLock', 'unreadable' ),
		nc( 'directory', '../.emptylocked', null, './', 'unreadable' ),
		nc( 'directory', '../.locked2', null, './', 'unreadable' ),
		nc( 'directory', '../.venv', null, 'bin/python', 'unreadable' ),
		nc( 'directory', '../.bashrc', null, './', 'unreadable' ),
		nc( 'directory', '..', null, '.x.php', 'unreadable' ),
	],
	'phphome: dangling links follow the rules of uploads/ in a home dir and of any dir elsewhere; dirs uid 33 can\'t open are unreadable; a dot link to a walked dir gives nothing'
);
eq( json_decode( raw( 'phphome.manifest.json' ), true )['checked'] ?? null, [ '/var/www/htdocs/index.php', '/var/www/lib/l.php' ], 'phphome: the dot link\'s target is checked by its own name' );
$sc = out( 'slowcode' );
eq( [ $sc['status'] ?? null, field( $sc, 'safe_to_upgrade' ), $sc['errors'] ?? null, $sc['files_checked'] ?? null, $sc['files_not_checked'] ?? null ], [ 'ok', false, 2, 3, 1 ], 'slowcode: a code-named file past COMPAT_FILE_TIMEOUT doesn\'t stop the scan' );
eq( report( 'slowcode' )['not_checked'] ?? null, [ nc( 'plugin', 'p', null, 'slow.php', 'timeout' ) ], 'slowcode: the slow file alone is timeout; its batch neighbours are checked' );
check( false !== strpos( raw( 'slowcode.stderr' ), ' capped' ), 'slowcode: the batch run was capped' );
check( ( $sc['duration_s'] ?? 99 ) < 60, 'slowcode: the scan ends soon after the caps (' . ( $sc['duration_s'] ?? '?' ) . ' s)' );
$bs = out( 'bigstdin' );
eq( [ $bs['status'] ?? null, field( $bs, 'safe_to_upgrade' ), $bs['errors'] ?? null, $bs['files_checked'] ?? null, $bs['files_not_checked'] ?? null ], [ 'ok', false, 1, 2, 1 ], 'bigstdin: verdict and counts' );
$r = report( 'bigstdin' );
eq( array_map( static function ( $f ) { return [ $f['file'], $f['line'] ]; }, comp_of( $r, 'plugin', 'p' )['findings'] ?? [] ), [ [ 'BIG.PHP', 40002 ] ], 'bigstdin: a 1 MiB STDIN file is read to its last line' );
eq( $r['not_checked'] ?? null, [ nc( 'plugin', 'p', null, 'HUGE.PHP', 'memory' ) ], 'bigstdin: a STDIN file over 16 MiB isn\'t copied: memory' );
$e = out( 'est-bigstdin' );
eq( [ $e['php_files'] ?? null, $e['inputs']['stdin_files'] ?? null ], [ 3, 1 ], 'est-bigstdin: the file over the STDIN cap is no PHPCS run' );

// Every ok scan writes manifest.json; its checked/not_checked match the counts, and every code file of the tree, by the
// manifest's own rules, is covered (tests/manifest-check.php ran against the scanned tree).
$manifests = 0;
foreach ( glob( "$dir/*.stdout" ) as $f ) {
	$name = basename( $f, '.stdout' );
	$doc  = json_decode( (string) file_get_contents( $f ), true );
	if ( ! is_array( $doc ) || 'ok' !== ( $doc['status'] ?? null ) || ! empty( $doc['estimate'] ) || 'nomanifest' === $name ) {
		check( ! is_file( "$dir/$name.manifest.json" ), "$name: no manifest unless the scan is ok" );
		continue;
	}
	$manifests++;
	foreach ( [ 'mcheck' => 'uid 33', 'mcheck-root' => 'root' ] as $ext => $who ) {
		$mc = json_decode( raw( "$name.$ext" ), true );
		check( is_array( $mc ), "$name: manifest checked as $who (" . trim( substr( raw( "$name.$ext" ), 0, 300 ) ) . ')' );
		eq( $mc['problems'] ?? null, [], "$name: every code file is checked or under not_checked, or exempt (walked as $who)" );
	}
	eq( [ $mc['checked'] ?? null, $mc['not_checked'] ?? null ], [ $doc['files_checked'], $doc['files_not_checked'] ], "$name: manifest counts equal files_checked and files_not_checked" );
	$m = json_decode( raw( "$name.manifest.json" ), true );
	eq( $m['excluded'] ?? null, [], "$name: manifest excluded is empty" );
}
check( $manifests >= 40, "manifests checked: $manifests" );
$m = json_decode( raw( 'sniff.manifest.json' ), true );
eq( array_slice( array_keys( (array) $m ), 0, 9 ), [ 'v', 'code_extensions', 'extensions_case_insensitive', 'phar_regex', 'sniff', 'roots', 'excluded', 'old_releases', 'core' ], 'manifest: keys' );
eq( [ $m['sniff']['bytes'] ?? null, $m['sniff']['scope'] ?? null ], [ 8192, 'except_skipped_dirs' ], 'manifest: sniff window and scope' );
sort( $m['checked'] );
eq(
	$m['checked'],
	array_map(
		static function ( $f ) {
			return "/var/www/htdocs/wp-content/plugins/p/$f";
		},
		[ 'big-mixed.tpl', 'bin/tool', 'p.php', 'tpl.php', 'views/admin.tpl', 'views/bom.html', 'views/warn.html' ]
	),
	'manifest: sniff checked (the link a-tpl.txt as its target tpl.php)'
);
eq( json_decode( raw( 'wpcfg-parent.manifest.json' ), true )['checked'] ?? null, [ '/var/www/wp-config.php', '/var/www/htdocs/wp-content/plugins/p/p.php' ], 'manifest: the parent wp-config.php WordPress loads is checked' );
$m = json_decode( raw( 'php-rel.manifest.json' ), true );
eq( [ $m['old_releases'] ?? null, $m['roots'] ?? null ], [ [ '/var/www/htdocs/releases/1/' ], [ '/var/www/' ] ], 'manifest: php old releases and root' );
eq( report( 'php-rel' )['excluded_old_releases'] ?? null, [ '/var/www/htdocs/releases/1' ], 'php-rel: the old release in the report' );
$m = json_decode( raw( 'full.manifest.json' ), true );
eq( $m['core']['roots'] ?? null, [ '/var/www/htdocs/releases/1/' ], 'manifest: core root is the resolved WordPress root' );
check( ! preg_grep( '#/releases/1/(wp-includes/|wp-settings\.php$)#', $m['checked'] ?? [] ), 'manifest: root core is never checked' );
check( in_array( '/var/www/htdocs/releases/1/wp-content/plugins/hardlink/h1.php', $m['checked'] ?? [], true ) xor in_array( '/var/www/htdocs/releases/1/wp-content/plugins/hardlink/h2.php', $m['checked'] ?? [], true ), 'manifest: a hard-linked file is listed once' );
$m = json_decode( raw( 'nested.manifest.json' ), true );
eq( $m['not_checked'] ?? null, [ '/var/www/htdocs/old/', '/var/www/htdocs/wp-content/plugins/fakecore/' ], 'manifest: nested installs are directory entries' );

// The whole of /var/www, and every install judged by its version.

/** The report's installs as "dir version live". */
function installs( string $name ): array {
	return array_map(
		static function ( $i ) {
			return $i['dir'] . ' ' . $i['version'] . ( $i['live'] ? ' live' : '' );
		},
		report( $name )['wordpress_installs'] ?? [ 'missing' ]
	);
}

/** [ status, verdict, errors, files_checked, files_not_checked ] of a run. */
function counts( string $name ): array {
	$d = out( $name );
	return [ $d['status'] ?? null, field( $d, 'safe_to_upgrade' ), $d['errors'] ?? null, $d['files_checked'] ?? null, $d['files_not_checked'] ?? null ];
}

$wa = report( 'wpapp' );
eq( counts( 'wpapp' ), [ 'ok', false, 5, 7, 1 ], 'wpapp: everything in /var/www beside the WordPress root is scanned' );
eq( finding_files( $wa ), [ 'directory:::.wp-cli/packages/vendor/x/legacy.php', 'directory:::adminer.php', 'directory:htdocs-backup::wp-content/plugins/q/q.php', 'directory:vendor::autoload.php', 'other:::uploads/u.php' ], 'wpapp: vendor/, adminer.php, the copy\'s plugin, a WP-CLI package; uploads/ by name only' );
eq( $wa['not_checked'] ?? null, [ nc( 'directory', 'htdocs-backup', null, './', 'nested_wordpress' ) ], 'wpapp: the copy\'s 6.1 core isn\'t supported: nested_wordpress' );
eq( installs( 'wpapp' ), [ '/var/www/htdocs 6.8.3 live', '/var/www/htdocs-backup 6.1.1' ], 'wpapp: both installs with their versions, the live one first' );
eq( [ counts( 'wpapp-supported' ), report( 'wpapp-supported' )['not_checked'] ?? null ], [ [ 'ok', false, 5, 7, 0 ], [] ], 'wpapp-supported: a supported branch\'s core is left out silently' );
eq( out( 'est-wpapp' )['php_files'] ?? null, 8, 'est-wpapp: counts equal the scan' );
$r5 = report( 'r5call' );
eq( [ counts( 'r5call' ), array_key_exists( 'phars', $r5 ) || array_key_exists( 'excluded_old_releases', $r5 ), installs( 'r5call' ) ], [ [ 'ok', false, 5, 7, 1 ], false, [ '/var/www/htdocs 6.8.3 live', '/var/www/htdocs-backup 6.1.1' ] ], 'r5call: a v3.11.1 call: no supported branches, no phar or release keys' );
eq( counts( 'nolive' ), [ 'ok', false, 2, 2, 0 ], 'nolive: the scan path isn\'t an install: no live root, so uploads/ is sniffed; the install below it is supported' );
eq( installs( 'nolive' ), [ '/var/www/htdocs/wp 6.8.1' ], 'nolive: no live install' );
eq( [ counts( 'phpwpcore' ), installs( 'phpwpcore' ) ], [ [ 'ok', true, 0, 2, 0 ], [ '/var/www/htdocs/blog 6.8.3' ] ], 'phpwpcore: WordPress inside a php site: its core judged by version, not scanned' );
eq( [ counts( 'phpwpcore-old' ), report( 'phpwpcore-old' )['not_checked'] ?? null ], [ [ 'ok', null, 0, 2, 1 ], [ nc( 'directory', 'htdocs/blog', null, './', 'nested_wordpress' ) ] ], 'phpwpcore-old: without a supported branch, nested_wordpress' );
eq( [ counts( 'r5call-php' ), array_key_exists( 'phars', report( 'r5call-php' ) ) ], [ [ 'ok', null, 0, 2, 1 ], false ], 'r5call-php: a v3.11.1 call on a php site' );
eq( [ counts( 'mountcore' ), installs( 'mountcore' ) ], [ [ 'ok', true, 0, 1, 0 ], [ '/var/www/htdocs 6.1.1 live' ] ], 'mountcore: the version is read where PHP reads it, through a mount over wp-includes' );

eq( [ counts( 'wpold-served' ), report( 'wpold-served' )['excluded_old_releases'] ?? null ], [ [ 'ok', true, 0, 1, 0 ], [ '/var/www/htdocs/releases/1', '/var/www/htdocs/releases/2' ] ], 'wpold-served: nginx serves current: the old releases are left out' );
foreach ( [ 'wpold-noserved', 'wpold-above', 'wpold-r5' ] as $name ) {
	eq( [ counts( $name ), finding_files( report( $name ) ) ], [ [ 'ok', false, 2, 3, 0 ], [ 'directory:htdocs::releases/1/wp-content/plugins/old/old.php', 'directory:htdocs::releases/2/x.php' ] ], "$name: not sure, above current, or a v3.11.1 call: every release scanned" );
}
eq( report( 'wpold-noserved' )['excluded_old_releases'] ?? null, [], 'wpold-noserved: none left out' );
eq( out( 'phpold-noserved' )['errors'] ?? null, 3, 'phpold-noserved: an empty COMPAT_SERVED leaves no release out on php sites either' );

$er = report( 'extraroot' );
eq( counts( 'extraroot' ), [ 'ok', false, 2, 3, 0 ], 'extraroot: uploads linked into a mounted dir is followed; the other mount is searched by name' );
eq( finding_files( $er ), [ 'directory:/srv/shared::lib/y.inc', 'other:::uploads/2026/x.php' ], 'extraroot: findings by the link\'s path, and by the mount\'s' );
eq( json_decode( raw( 'extraroot.manifest.json' ), true )['roots'] ?? null, [ '/var/www/', '/mnt/media/', '/srv/shared/' ], 'extraroot: manifest roots' );
eq( [ counts( 'extraroot-none' ), report( 'extraroot-none' )['not_checked'] ?? null ], [ [ 'ok', null, 0, 1, 1 ], [ nc( 'other', '', null, 'uploads/', 'unreadable' ) ] ], 'extraroot-none: without the mount the link dangles: unreadable' );

eq( counts( 'require' ), [ 'ok', null, 0, 1, 7 ], 'require: prepend and append targets the scan didn\'t read give no verdict' );
eq(
	array_column( report( 'require' )['not_checked'] ?? [], 'file' ),
	[ '/usr/local/etc/php/xhprof.php', '/var/www/htdocs/wp-includes/version.php', '/var/www/htdocs/wp-cli.phar', '/var/www/htdocs/notes.txt', 'rel.php', 'waf.php', '/opt/append.php' ],
	'require: outside the site, in core, a phar, not code, relative; from .user.ini files too, also in uploads/ (the scanned wordfence-waf.php and `none` give nothing)'
);

foreach ( [ 'phar-info' => null, 'phar-named' => 'boot.php', 'phar-upper' => 'boot.php', 'phar-split' => 'boot.php' ] as $name => $by ) {
	$r     = report( $name );
	$phars = [ '/var/www/htdocs/wp-content/plugins/p/lib.phar', '/var/www/htdocs/wp-cli.phar' ];
	$named = null === $by ? null : "/var/www/htdocs/wp-content/plugins/p/$by";
	$nc    = null === $by ? [] : [ nc( 'plugin', 'p', null, 'lib.phar', 'phar' ), nc( 'directory', 'htdocs', null, 'wp-cli.phar', 'phar' ) ];
	eq( [ $r['phars'] ?? null, field( $r, 'phar_named_by' ), $r['not_checked'] ?? null ], [ null === $by ? $phars : [], $named, $nc ], "$name: phars are information unless scanned code names one" );
	eq( field( out( $name ), 'safe_to_upgrade' ), null === $by ? true : null, "$name: verdict" );
}
$r = report( 'phar-r5call' );
eq( [ array_key_exists( 'phars', $r ), array_column( $r['not_checked'] ?? [], 'reason' ) ], [ false, [ 'phar', 'phar' ] ], 'phar-r5call: a v3.11.1 call keeps phar entries' );

$li = report( 'lint' );
eq( counts( 'lint' ), [ 'ok', false, 3, 7, 1 ], 'lint: verdict and counts' );
eq(
	array_map( static function ( $f ) { return $f['file'] . ':' . $f['line'] . ':' . $f['source']; }, comp_of( $li, 'plugin', 'p' )['findings'] ?? [] ),
	[ 'attr.php:3:CompatScanner.Syntax.ParseError', 'pipe.php:2:CompatScanner.Syntax.ParseError', 'unclosed.php:3:CompatScanner.Syntax.ParseError' ],
	'lint: `#[` before code, the pipe operator and an unclosed comment fail on 8.4; an <?xml template and two files declaring one function don\'t'
);
eq( $li['not_checked'] ?? null, [ nc( 'plugin', 'p', null, 'views/broken.tpl', 'php_tag' ) ], 'lint: a parse error after other text is php_tag' );
eq( [ counts( 'lint-85' ), array_column( report( 'lint-85' )['not_checked'] ?? [], 'reason' ) ], [ [ 'ok', null, 0, 4, 4 ], [ 'unparseable', 'unparseable', 'unparseable', 'unparseable' ] ], 'lint-85: above the scanner\'s PHP a lint failure is unparseable, not an error' );
$l74 = report( 'lint-74' );
$l74sources = array_column( comp_of( $l74, 'plugin', 'p' )['findings'] ?? [], 'source' );
eq( [ in_array( 'CompatScanner.Syntax.ParseError', $l74sources, true ), array_column( $l74['not_checked'] ?? [], 'file' ) ], [ false, [ 'views/broken.tpl' ] ], 'lint-74: targets before 8.0 aren\'t linted (broken.tpl is PHPCS\'s own unparseable)' );

tool_error( 'badargs-served', 'bad arguments: COMPAT_SERVED must be', 2, false );
tool_error( 'badargs-supported', 'bad arguments: COMPAT_WP_SUPPORTED must be', 2, false );
tool_error( 'badargs-roots', 'bad arguments: COMPAT_EXTRA_ROOTS must be', 2, false );

echo "\n", $count - $fails, '/', $count, " checks passed\n";
exit( $fails ? 1 : 0 );
