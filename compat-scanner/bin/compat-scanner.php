<?php
/**
 * Entrypoint of easyengine/compat-scanner.
 *
 * Usage: <scan|estimate> <wp|php> <site_container_fs_path> <version> <timeout>
 *
 * Prints exactly one JSON document on stdout. `ee site php-compat` in
 * site-command parses it; keep both in sync with INTERFACE.md.
 */

declare( strict_types=1 );

// Diagnostics never go to stdout, which carries only the JSON document.
ini_set( 'display_errors', 'stderr' );
ini_set( 'log_errors', '0' );
error_reporting( E_ALL );

const MOUNT_ROOT      = '/var/www';
const OUT_DIR         = '/out';
const TOOL_DIR        = '/opt/compat-scanner';
const PHPCS_BIN       = TOOL_DIR . '/vendor/squizlabs/php_codesniffer/bin/phpcs';
const REPORT_CLASS    = TOOL_DIR . '/src/LinesReport.php';
const CALIBRATION_DIR = TOOL_DIR . '/calibration';
// The scanner's own PHPCS checks, added to PHPCompatibility's.
const SNIFFS_DIR      = TOOL_DIR . '/src/CompatScanner';
const JSON_FLAGS      = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE;
// Walked only for code names (see skipped()), and only in the WordPress root's own wp-content for TOP_SKIPS.
// upgrade-temp-backup: WordPress' rollback copies of updated plugins and themes (6.3+).
const TOP_SKIPS       = [ 'uploads', 'cache', 'upgrade', 'upgrade-temp-backup' ];
const ANY_SKIPS       = [ 'node_modules', '.git' ];
const STRUCTURAL      = [ 'plugins', 'themes', 'mu-plugins' ];
// Core of the WordPress root (wp-settings.php and wp-includes/ in the scanned directory): never scanned.
const CORE_DIRS       = [ 'wp-admin', 'wp-includes' ];
// index.php isn't here: it is tiny, and EE validates the root's own loader too.
const CORE_FILES      = [ 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php', 'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php' ];
const TYPE_ORDER      = [ 'plugin' => 0, 'theme' => 1, 'mu-plugin' => 2, 'directory' => 3, 'other' => 4 ];
// Same as EE's REPORT_MAX: EE rejects a larger report anyway.
const REPORT_MAX      = 134217728;
// Slack over the cap for PHPCS's own report file: a header line (up to ~6 KB) per file.
const FSIZE_SLACK     = 2097152;
const HEADER_MAX      = 6144;
const LINE_MAX        = 1048576;
const BUFFER_MAX      = 262144;
// File extensions checked as PHP code, matched case-insensitively.
const CODE_EXTENSIONS = [ 'php', 'inc', 'phtml', 'module', 'install', 'theme', 'engine', 'php5', 'php7' ];
// Other files are read this far for a PHP open tag.
const SNIFF_BYTES     = 8192;
// A file PHPCS reads through STDIN is copied to /out first; past this it is refused by size (`memory`), not copied.
// Real PHP code of 8 MiB already exceeds 960M, though a mostly-comment file that large could be checked.
const STDIN_MAX       = 16777216;
// Bit of a file list entry's length field: the file has a PHP tag after other text, so its findings can't be trusted.
const MIXED_FLAG      = 0x80000000;
// What sniff() matches in a file's first SNIFF_BYTES, as one regex (no NUL anywhere, then an open tag), for the manifest.
const SNIFF_REGEX     = '/\\A(?=[^\\x00]*\\z)[\\s\\S]*?<\\?(?:php(?:\\s|\\z)|=)/i';
const PHAR_REGEX      = '/\\.phar(?:\\.(?:tar|zip))?(?:\\.(?:gz|bz2))?\\z/i';
// Backup copies: never read, so a stale copy can't give "not safe" (a copy code includes is missed, accepted).
const BACKUP_EXTENSIONS = [ 'bak', 'orig', 'old', 'save', 'swp', 'log', 'sql', 'dist' ];
// The www-data home in /var/www: searched by name only, like uploads/.
const HOME_DIRS = [ '.wp-cli', '.composer', '.cache', '.config', '.local', '.npm', '.ssh' ];
// Never PHP templates, so not sniffed: docs, scripts and styles quote `<?php` (and one such file hangs a sniff).
const NO_SNIFF_EXTENSIONS = [ 'md', 'markdown', 'txt', 'rst', 'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx', 'map', 'json', 'css', 'scss', 'sass', 'less', 'svg', 'xml', 'yml', 'yaml', 'lock', 'csv', 'po', 'pot', 'mo', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'ico', 'bmp', 'tif', 'tiff', 'woff', 'woff2', 'ttf', 'otf', 'eot', 'pdf', 'zip', 'gz', 'tgz', 'bz2', 'xz' ];
// Estimate time kept for calibration (two PHPCS runs, ~5 s on one CPU); at most a quarter of the deadline.
const CALIBRATION_RESERVE = 20;

class TimedOut extends RuntimeException {
}

class BadArgs extends RuntimeException {
}

class ToolError extends RuntimeException {
}

final class Scanner {

	/** @var array<string,mixed> */
	private $cfg;
	/** @var float */
	private $start;
	/** @var float */
	private $deadline;
	/** @var float */
	private $listDeadline;
	/** @var int */
	private $timeoutLabel;
	/** @var bool */
	private $isScan;

	/** @var array<int,array<string,mixed>> Components by index. */
	private $comps = [];
	/** @var array<string,int> */
	private $compKeys = [];
	/** @var string|null Real path of the content root (wp-content, or htdocs for php sites). */
	private $contentReal;
	/** @var string|null Real path of the directory scanned (wp: the WordPress directory; php: htdocs). */
	private $rootReal;
	/** @var array<string,bool> Directories holding WordPress core, by real path. */
	private $coreDirs = [];
	/** @var string|null Real path of the scan path when it is a WordPress install: the live root, whose core EE judges. */
	private $live;
	/** @var array<string,bool> Other WordPress installs whose core was met (and skipped), by real path. */
	private $nested = [];
	/** @var string[] Other installs whose core is left out silently: their branch supports the target. */
	private $leftOut = [];
	/** @var array<int,array{dir:string,version:string,live:bool}> */
	private $installs = [];
	/** @var string[] Prepend and append values of the .user.ini files met. */
	private $required = [];
	/** @var string[] /var/www and COMPAT_EXTRA_ROOTS: what links may resolve into. */
	private $roots;
	/** @var string[] Real paths of the releases `current` doesn't point to, when nginx serves through it. */
	private $oldReleases = [];
	/** @var array<int,array<int,bool>> Visited directories by device and inode. */
	private $seenDirs = [];
	/** @var array<int,array<int,bool>> Listed files by device and inode. */
	private $seenFiles = [];
	/** @var array<string,string|false> Real paths of the site path and content root when listed. */
	private $pins = [];
	/** @var int */
	private $ticks = 0;

	/** @var int */
	private $listedFiles = 0;
	/** @var int */
	private $listedBytes = 0;
	/** @var int */
	private $notCheckedCount = 0;
	/** @var int Data-only files (`<?php exit; ?>` + data), checked at listing without PHPCS. */
	private $dataFiles = 0;
	/** @var int */
	private $dataBytes = 0;
	/** @var int Listed files deleted before their batch. */
	private $dropped = 0;
	/** @var int Phars collected, when they may be information (spooled to work/phars in a scan). */
	private $pharCount = 0;
	/** @var string|null The first scanned file naming a phar, which makes every phar not_checked. */
	private $pharNamedBy;
	/** @var int Listed files PHPCS reads through STDIN, one run each (for the estimate). */
	private $stdinFiles = 0;
	/** @var bool Listing the code files found in a skipped directory (where caches keep data-only files). */
	private $inSkipped = false;
	/** @var array<string,string> Manifest spools (`checked`, `not_checked`) not yet written, by name. */
	private $manBuf = [ 'checked' => '', 'not_checked' => '', 'information' => '' ];
	/** @var string[] Real paths (with `/`) of the directories searched by name only, where nothing is sniffed. */
	private $skippedDirs = [];

	/** @var string */
	private $work = '';
	/** @var resource|null File list spool (scan mode). */
	private $listFh;
	/** @var string */
	private $listBuf = '';
	/** @var int Bytes of findings and not_checked entries spooled so far. */
	private $reportBytes = 0;

	public function __construct( array $cfg ) {
		$this->cfg    = $cfg;
		$this->isScan = 'scan' === $cfg['mode'];
		$this->roots  = array_merge( [ MOUNT_ROOT ], $cfg['extra_roots'] );
		$this->start  = microtime( true );
		$limit        = $this->isScan ? $cfg['timeout'] : $cfg['estimate_timeout'];

		$this->timeoutLabel = $limit;
		$this->deadline     = $this->start + $limit;
		$this->listDeadline = $this->isScan ? $this->deadline : $this->deadline - min( CALIBRATION_RESERVE, $limit / 4 );
	}

	public function run(): array {
		if ( $this->isScan ) {
			$this->work = OUT_DIR . '/.work';
			$this->makeWork();
			$this->listFh = fopen( $this->work . '/files', 'w+b' );
			if ( false === $this->listFh ) {
				throw new ToolError( 'output directory not writable' );
			}
		}

		if ( $this->cfg['debug'] && function_exists( 'posix_getrlimit' ) ) {
			$this->debug( 'core limit ' . ( posix_getrlimit()['soft core'] ?? '?' ) );
		}
		$this->listFiles();

		// WordPress core is code too: its version must reach EE.
		if ( 0 === $this->listedFiles && 0 === $this->notCheckedCount && 0 === $this->dataFiles && 0 === $this->pharCount && ! $this->installs ) {
			$this->removeWork();
			return $this->reduced( 'no_code_found' );
		}
		if ( ! $this->isScan ) {
			return $this->estimate();
		}

		$this->flushList();
		$this->readHeaders();
		return $this->scan();
	}

	// ---------------------------------------------------------------- listing

	/** Lists the files in scope: the site's root (WordPress or htdocs) first, then the rest of /var/www. */
	private function listFiles(): void {
		$this->pins[ $this->cfg['path'] ] = @realpath( $this->cfg['path'] );
		$served = $this->servedPath();
		if ( '' !== $served ) {
			$this->pins[ $served ] = realpath( $served );
			$this->oldReleases     = $this->oldReleases( $served );
		}
		if ( 'php' === $this->cfg['site_type'] ) {
			// A missing or bad htdocs (its own entry) leaves the code beside it, the mounts and the prepend targets to check.
			$root    = MOUNT_ROOT . '/htdocs';
			$entered = $this->enterRoot( $root );
			if ( $entered ) {
				$this->rootReal = $this->contentReal;
				$other          = $this->comp( 'other', '', null, $root );
				$entries        = $this->readDir( $root );
				if ( null === $entries ) {
					$this->notChecked( $other, './', 'unreadable' );
				} else {
					$this->scanTop( $root, $entries, $other, '' );
				}
			}
			$this->scanBeside( $this->comp( 'directory', '..', null, MOUNT_ROOT ), '../', $entered ? [] : [ 'htdocs' ] );
		} else {
			$top = $this->wpDir( $this->cfg['path'] );
			if ( null !== $top ) {
				$this->live = $this->coreDir( $this->rootReal ) ? $this->rootReal : null;
				$this->wpTree( $this->cfg['path'], $top );
			}
			$this->scanBeside( $this->comp( 'directory', '', null, MOUNT_ROOT ), '' );
		}
		// Directories the php container mounts outside /var/www: searched by name, after /var/www so a link into one
		// keeps its own component.
		foreach ( $this->cfg['extra_roots'] as $root ) {
			$comp = $this->comp( 'directory', $root, null, $root );
			if ( is_dir( $root ) ) {
				$this->skipped( $root, '.', $comp );
			} else {
				$this->notChecked( $comp, './', 'unreadable' );
			}
		}
		// PHP reads a .user.ini for the scripts below it in the directories left out too: core and old releases.
		foreach ( $this->leftOutDirs() as $dir ) {
			$this->iniIn( $dir );
		}
		$this->checkRequired();
		$this->judgeInstalls();
	}

	/**
	 * Files PHP loads before or after every script (COMPAT_REQUIRE from EE's ini files, and every .user.ini's): each
	 * must be a file the scan reads, else it is unreadable, naming the value. Nothing is scanned for them.
	 */
	private function checkRequired(): void {
		$other = $this->comp( 'other', '', null, MOUNT_ROOT );
		foreach ( array_unique( array_merge( $this->cfg['require'], $this->required ) ) as $target ) {
			$st   = '/' === $target[0] && is_file( $target ) ? stat( $target ) : false;
			$seen = false === $st ? null : ( $this->seenFiles[ $st['dev'] ][ $st['ino'] ] ?? null );
			if ( true !== $seen && 'm' !== $seen ) {
				$this->notChecked( $other, $target, 'unreadable', $target );
			}
		}
	}

	/** @return string[] Directories the walk leaves out whole: the core dirs of every install met, and the old releases. */
	private function leftOutDirs(): array {
		$dirs = $this->oldReleases;
		foreach ( array_merge( null === $this->live ? [] : [ $this->live ], array_keys( $this->nested ) ) as $install ) {
			foreach ( CORE_DIRS as $core ) {
				$dirs[] = $install . '/' . $core;
			}
		}
		return $dirs;
	}

	/** Reads every .user.ini under a directory, found by name; links to directories aren't followed. */
	private function iniIn( string $dir ): void {
		$stack = [ $dir ];
		while ( $stack ) {
			$d = array_pop( $stack );
			foreach ( (array) $this->readDir( $d ) as $name ) {
				$path = $d . '/' . $name;
				if ( is_dir( $path ) && ! is_link( $path ) ) {
					$stack[] = $path;
				} elseif ( '.user.ini' === $name ) {
					$this->userIniOnce( $path, (string) @realpath( $path ) );
				}
			}
		}
	}

	/** userIni() once per file, whichever route reaches it. */
	private function userIniOnce( string $path, string $real ): void {
		$st = @stat( $real );
		if ( false === $st || isset( $this->seenFiles[ $st['dev'] ][ $st['ino'] ] ) ) {
			return;
		}
		$this->seenFiles[ $st['dev'] ][ $st['ino'] ] = 'ini';
		$this->userIni( $path, $real );
	}

	/**
	 * Collects a .user.ini's auto_prepend_file and auto_append_file values. A line too long to read, or zend.multibyte or
	 * zend.script_encoding (PHP then reads the code in another encoding than PHPCS), makes the file itself an unreadable
	 * entry, as EE does for its ini files.
	 */
	private function userIni( string $path, string $real ): void {
		$fh = open_regular( $real );
		if ( null === $fh ) {
			return;
		}
		$keys   = '(auto_(?:prepend|append)_file|zend\.multibyte|zend\.script_encoding)';
		$unsure = false;
		foreach ( lines( $fh ) as $n => $line ) {
			if ( null === $line ) {
				$unsure = true;
				continue;
			}
			// As PHP's ini scanner reads it: a BOM first, a bare \r ends a line, `[section] key=` on one line.
			$line = 0 === $n ? (string) preg_replace( '/^\xEF\xBB\xBF/', '', $line ) : $line;
			foreach ( explode( "\r", $line ) as $part ) {
				$value = preg_match( '/^\s*(?:\[[^\]]*\]\s*)*' . $keys . '\s*=(.*)$/i', $part, $m ) ? ini_value( $m[2] ) : '';
				$key   = strtolower( $m[1] ?? '' );
				if ( '' === $value || ( 'zend.multibyte' === $key && '0' === $value ) ) {
					continue;
				}
				if ( 0 === strpos( $key, 'auto_' ) ) {
					$this->required[] = $value;
				} else {
					$unsure = true;
				}
			}
		}
		fclose( $fh );
		if ( $unsure ) {
			$this->notChecked( $this->comp( 'other', '', null, MOUNT_ROOT ), $path, 'unreadable', $real );
		}
	}

	/**
	 * What nginx serves, which decides whether old releases are left out: COMPAT_SERVED; a v3.11.1 call has none, and
	 * then php sites use the scan path and WordPress sites leave nothing out. '' leaves nothing out.
	 */
	private function servedPath(): string {
		if ( false !== $this->cfg['served'] ) {
			return $this->cfg['served'];
		}
		return 'php' === $this->cfg['site_type'] ? $this->cfg['path'] : '';
	}

	/**
	 * Another install's core is left out, silently when EE says its branch supports the target, else as one
	 * nested_wordpress entry. Every install, the live one first, goes to the report with its version.
	 */
	private function judgeInstalls(): void {
		if ( null !== $this->live ) {
			$this->installs[] = [ 'dir' => $this->live, 'version' => wp_version( $this->live ), 'live' => true ];
		}
		$nested = array_keys( $this->nested );
		sort( $nested, SORT_STRING );
		foreach ( $nested as $dir ) {
			$version          = wp_version( $dir );
			$this->installs[] = [ 'dir' => $dir, 'version' => $version, 'live' => false ];
			if ( in_array( wp_branch( $version ), $this->cfg['wp_supported'], true ) ) {
				$this->leftOut[] = $dir;
			} else {
				$this->notChecked( $this->comp( 'directory', $this->relMount( $dir ), null, $dir ), './', 'nested_wordpress' );
			}
		}
	}

	/**
	 * The WordPress directory. Plugins, themes and mu-plugins of every content root are walked before anything else, so
	 * a directory reached both from there and through another path belongs to the component; the rest of the WordPress
	 * directory (everything but the live root's core) comes last.
	 */
	private function wpTree( string $wp, array $top ): void {
		$root   = $wp . '/wp-content';
		$config = $this->wpConfig( $wp );
		if ( null !== $config ) {
			// Reported by its real path relative to /var/www (the file to edit), e.g. htdocs/wp-config.php; one linked out of
			// /var/www by the link, which visit() follows.
			$real = @realpath( $config );
			$path = false !== $real && 0 === strpos( $real, MOUNT_ROOT . '/' ) ? $real : $config;
			$this->visit( $path, 'wp-config.php', $this->comp( 'other', 'wp-config.php', null, MOUNT_ROOT ) );
		}

		$main       = null;
		$candidates = [];
		if ( $this->enterContent( $root ) ) {
			$main = $this->wpRoot( $root, null );
			if ( null === $main['entries'] ) {
				$this->notChecked( $main['other'], './', 'unreadable' );
				$main = null;
			} else {
				// Branch roots: other direct children holding plugins/ or themes/. languages/ has those for translations.
				foreach ( $main['entries'] as $name ) {
					if ( in_array( $name, STRUCTURAL, true ) || in_array( $name, $main['skips'], true ) || 'languages' === $name ) {
						continue;
					}
					$path = $root . '/' . $name;
					if ( $this->contentLike( $path ) ) {
						$candidates[] = [ (string) $name, $path, true ];
					}
				}
			}
		}

		// Content dirs beside wp-content (a moved WP_CONTENT_DIR) are branch roots too, named by their path under /var/www.
		$rest = [];
		foreach ( $top as $name ) {
			if ( 'wp-content' === $name ) {
				continue;
			}
			$path = $wp . '/' . $name;
			if ( ! in_array( $name, ANY_SKIPS, true ) && $this->contentLike( $path ) ) {
				$candidates[] = [ $this->relMount( $path ), $path, false ];
			} else {
				$rest[] = $name;
			}
		}

		// Main root first, so its plugins and themes win over a branch link to them.
		if ( null !== $main ) {
			$main = $this->structural( $main );
		}
		$branches = [];
		$beside   = [];
		foreach ( $candidates as list( $name, $path, $inContent ) ) {
			if ( ! $this->markDir( (string) $this->resolve( $path ) ) ) {
				continue;
			}
			$b = $this->wpRoot( $path, $name );
			if ( null === $b['entries'] ) {
				$this->notChecked( $b['other'], './', 'unreadable' );
			}
			if ( $inContent ) {
				$branches[ $name ] = $this->structural( $b );
			} else {
				$beside[] = $this->structural( $b );
			}
		}

		if ( null !== $main ) {
			$this->others( $main, $branches );
		}
		foreach ( $beside as $b ) {
			$this->others( $b, [] );
		}
		// Everything else in the WordPress directory but core: custom endpoints, a second app, a linked target's siblings.
		$this->scanTop( $wp, $rest, $this->comp( 'directory', $this->relMount( $wp ), null, $wp ), $this->relMount( $wp ) . '/' );
	}

	/** A directory in scope holding plugins/ or themes/: a content root. */
	private function contentLike( string $path ): bool {
		$real = $this->resolve( $path );
		return null !== $real && is_dir( $real ) && ! $this->outOfScope( $real ) && ( is_dir( $path . '/plugins' ) || is_dir( $path . '/themes' ) );
	}

	/** Path relative to /var/www, as given (unresolved); a path outside it stays absolute. */
	private function relMount( string $path ): string {
		if ( MOUNT_ROOT === $path ) {
			return '';
		}
		return 0 === strpos( $path, MOUNT_ROOT . '/' ) ? substr( $path, strlen( MOUNT_ROOT ) + 1 ) : $path;
	}

	/**
	 * Enters the WordPress directory.
	 *
	 * @return string[]|null Its entries, or null when there is nothing to walk.
	 */
	private function wpDir( string $wp ): ?array {
		$real = @realpath( $wp );
		if ( false === $real || ! is_dir( $real ) || ! $this->inside( $real ) ) {
			$this->badRoot( $wp, $real, $wp . '/wp-content' );
			return null;
		}
		$this->rootReal = $real;
		$this->markDir( $real );
		$entries = $this->readDir( $wp );
		if ( null === $entries ) {
			// Reported as wp-content's root, as before; in the manifest it is the WordPress directory that can't be listed.
			$this->notChecked( $this->comp( 'other', '', null, $wp . '/wp-content' ), './', 'unreadable', $real . '/' );
		}
		return $entries;
	}

	/** True when wp-content is a directory inside the mount; a bad link to it is not_checked. */
	private function enterContent( string $root ): bool {
		if ( false === @lstat( $root ) && ! $this->denied( $root ) ) {
			return false;
		}
		$real = @realpath( $root );
		if ( false === $real || ! is_dir( $real ) || ! $this->inside( $real ) ) {
			$this->badRoot( $root, $real, $root );
			return false;
		}
		$this->pins[ $root ] = $real;
		$this->contentReal   = $real;
		$this->markDir( $real );
		return true;
	}

	/**
	 * What lies in /var/www beside the root (code above the public dir, a second app, the www-data home), as components
	 * named $prefix . name; $skip: a root already reported. Links come last, so a directory is listed under its own name
	 * before a link to it.
	 */
	private function scanBeside( int $loose, string $prefix, array $skip = [] ): void {
		$this->markDir( MOUNT_ROOT );
		$entries = $this->readDir( MOUNT_ROOT );
		if ( null === $entries ) {
			$this->notChecked( $loose, './', 'unreadable' );
			return;
		}
		$links = [];
		foreach ( array_diff( $entries, $skip ) as $name ) {
			if ( is_link( MOUNT_ROOT . '/' . $name ) ) {
				$links[] = $name;
			} elseif ( in_array( $name, HOME_DIRS, true ) ) {
				$this->skipped( MOUNT_ROOT . '/' . $name, $name, $loose );
			} else {
				$this->scanTop( MOUNT_ROOT, [ $name ], $loose, $prefix );
			}
		}
		$this->scanTop( MOUNT_ROOT, $links, $loose, $prefix );
	}

	/**
	 * The wp-config.php WordPress loads: in its (resolved) directory, else in the
	 * parent when that holds no wp-settings.php; the unresolved parent last
	 * (`htdocs/wp-config.php` above a `current` link).
	 */
	private function wpConfig( string $wpDir ): ?string {
		$real = @realpath( $wpDir );
		if ( false === $real ) {
			return null;
		}
		if ( file_exists( $real . '/wp-config.php' ) ) {
			return $real . '/wp-config.php';
		}
		foreach ( array_unique( [ dirname( $real ), dirname( $wpDir ) ] ) as $parent ) {
			if ( $this->inside( $parent ) && file_exists( $parent . '/wp-config.php' ) && ! file_exists( $parent . '/wp-settings.php' ) ) {
				return $parent . '/wp-config.php';
			}
		}
		return null;
	}

	/**
	 * CI/CD layout of a php site: the first `current` symlink on the public path,
	 * pointing at a direct child of a real `releases/` dir next to it (as site-command's
	 * backup detects it). Returns the other releases, which aren't scanned.
	 *
	 * @return string[]
	 */
	private function oldReleases( string $publicDir ): array {
		$path = MOUNT_ROOT;
		foreach ( explode( '/', substr( $publicDir, strlen( MOUNT_ROOT ) + 1 ) ) as $part ) {
			$parent = $path;
			$path  .= '/' . $part;
			if ( 'current' !== $part || ! is_link( $path ) ) {
				continue;
			}
			$live      = @realpath( $path );
			$parentRaw = @realpath( $parent );
			if ( false === $live || false === $parentRaw ) {
				return [];
			}
			$releases = $parentRaw . '/releases';
			if ( is_link( $releases ) || ! is_dir( $releases ) || ! $this->inside( $releases ) || dirname( $live ) !== $releases ) {
				return [];
			}
			// A release holding the scan path is walked: EE's WordPress hint may name an old one (a stale wp-cli.yml path).
			$scan = realpath( $this->cfg['path'] ) . '/';
			$old  = [];
			foreach ( (array) $this->readDir( $releases ) as $name ) {
				$dir = $releases . '/' . $name;
				if ( $dir !== $live && ! is_link( $dir ) && is_dir( $dir ) && 0 !== strpos( $scan, $dir . '/' ) ) {
					$old[] = $dir;
				}
			}
			return $old;
		}
		return [];
	}

	/** True when the root exists as a directory inside the mount. */
	private function enterRoot( string $root ): bool {
		$real = @realpath( $root );
		if ( false === $real || ! is_dir( $real ) || ! $this->inside( $real ) ) {
			$this->badRoot( $root, $real, $root );
			return false;
		}
		$this->pins[ $root ] = $real;
		$this->contentReal   = $real;
		$this->markDir( $real );
		return true;
	}

	/**
	 * A root that may hold code though it can't be entered is not_checked, not no_code_found: one uid 33
	 * can't reach (EACCES on the way), or a link on the way that dangles or leaves the mount.
	 *
	 * @param string|false $real
	 */
	private function badRoot( string $root, $real, string $base ): void {
		$link = false;
		if ( false === $real || ! $this->inside( $real ) ) {
			for ( $p = $root; strlen( $p ) > strlen( MOUNT_ROOT ); $p = dirname( $p ) ) {
				if ( is_link( $p ) ) {
					$link = true;
					break;
				}
			}
		}
		if ( $link || ( false === $real && $this->denied( $root ) ) ) {
			$this->notChecked( $this->comp( 'other', '', null, $base ), './', 'unreadable' );
		}
	}

	private function denied( string $path ): bool {
		return function_exists( 'posix_access' ) && ! @posix_access( $path ) && 13 === posix_get_last_error();
	}

	/** A content root's `other` component, its entries and the names skipped in it (TOP_SKIPS only in the live root's wp-content). */
	private function wpRoot( string $path, ?string $branch ): array {
		return [
			'path'    => $path,
			'branch'  => $branch,
			'other'   => $this->comp( 'other', '', $branch, $path ),
			'entries' => $this->readDir( $path ),
			'skips'   => null === $branch && null !== $this->live ? array_merge( TOP_SKIPS, ANY_SKIPS ) : ANY_SKIPS,
			'plugins' => null,
			'themes'  => null,
		];
	}

	/** First pass over a content root: plugins, theme directories and mu-plugins. */
	private function structural( array $r ): array {
		foreach ( (array) $r['entries'] as $name ) {
			if ( ! in_array( $name, STRUCTURAL, true ) ) {
				continue;
			}
			$path = $r['path'] . '/' . $name;
			$real = $this->resolve( $path );
			if ( null !== $real && $this->outOfScope( $real ) ) {
				$this->unreadLink( $path, $real, $r['other'], $name );
				continue;
			}
			if ( null === $real || ! is_dir( $real ) || ! $this->markDir( $real ) ) {
				continue;
			}
			if ( 'plugins' === $name ) {
				$r['plugins'] = $this->scanPlugins( $path, $r['branch'], $r['other'] );
			} elseif ( 'themes' === $name ) {
				$r['themes'] = $this->scanThemes( $path, $r['branch'], $r['other'] );
			} else {
				$mu = $this->comp( 'mu-plugin', 'mu-plugins', $r['branch'], $path );
				$this->walk( $path, $mu );
			}
		}
		return $r;
	}

	/** Second pass: everything else under a content root, in sorted order. */
	private function others( array $r, array $branches ): void {
		foreach ( (array) $r['entries'] as $name ) {
			$path = $r['path'] . '/' . $name;
			if ( in_array( $name, $r['skips'], true ) ) {
				$this->skipped( $path, $name, $r['other'] );
				continue;
			}
			if ( in_array( $name, STRUCTURAL, true ) ) {
				$loose = 'themes' === $name ? $r['themes'] : ( 'plugins' === $name ? $r['plugins'] : null );
				if ( null !== $loose ) {
					// Loose files in themes/, and header-less ones in plugins/, belong to `other`.
					foreach ( $loose as $file ) {
						$this->visit( $path . '/' . $file, $file, $r['other'] );
					}
					continue;
				}
				$real = $this->resolve( $path );
				if ( null !== $real && is_dir( $real ) ) {
					continue; // Walked in the first pass, or already visited.
				}
			} elseif ( isset( $branches[ $name ] ) ) {
				$this->others( $branches[ $name ], [] );
				continue;
			}
			$this->visit( $path, $name, $r['other'] );
		}
	}

	/** @return string[] Loose files without a plugin header, left for the second pass. */
	private function scanPlugins( string $dir, ?string $branch, int $other ): array {
		$entries = $this->readDir( $dir );
		if ( null === $entries ) {
			$this->notChecked( $other, 'plugins/', 'unreadable' );
			return [];
		}

		// A plugin dir named node_modules or .git is a plugin like any other.
		$loose = [];
		foreach ( $entries as $name ) {
			$path = $dir . '/' . $name;
			$real = $this->resolve( $path );

			if ( null !== $real && is_dir( $real ) ) {
				if ( $this->outOfScope( $real ) ) {
					$this->unreadLink( $path, $real, $other, $this->rel( $other, $path ) );
				} elseif ( $this->markDir( $real ) ) {
					$comp = $this->comp( 'plugin', $name, $branch, $path, [ 'header' => 'plugin-dir', 'at' => $path ] );
					$this->walk( $path, $comp );
				}
				continue;
			}

			// Only a lowercase .php file can be a single-file plugin, as in WordPress.
			if ( $this->isPhpName( $name ) && ! $this->isPluginName( $name ) ) {
				$loose[] = $name;
				continue;
			}
			if ( null !== $real && ! $this->isPhpName( $name ) ) {
				$loose[] = $name; // Not code by name; `other` sniffs it.
				continue;
			}
			if ( null === $real && ! $this->linkMatters( $path, $name ) ) {
				continue;
			}
			// WordPress' `index.php` stub and other header-less files aren't plugins.
			if ( null !== $real ) {
				$this->tick();
				$head = read_head( $path );
				if ( null !== $head && null === header_value( str_replace( "\r", "\n", $head ), 'Plugin Name' ) ) {
					$loose[] = $name;
					continue;
				}
			}

			$comp = $this->comp( 'plugin', $name, $branch, $dir, [ 'header' => 'plugin-file', 'at' => $path ] );
			$this->visit( $path, $name, $comp );
		}
		return $loose;
	}

	/** @return string[] Loose entries left for the second pass. */
	private function scanThemes( string $dir, ?string $branch, int $other ): array {
		$entries = $this->readDir( $dir );
		if ( null === $entries ) {
			$this->notChecked( $other, 'themes/', 'unreadable' );
			return [];
		}

		$loose = [];
		foreach ( $entries as $name ) {
			$path = $dir . '/' . $name;
			$real = $this->resolve( $path );

			if ( null !== $real && is_dir( $real ) ) {
				if ( $this->outOfScope( $real ) ) {
					$this->unreadLink( $path, $real, $other, $this->rel( $other, $path ) );
				} elseif ( $this->markDir( $real ) ) {
					$comp = $this->comp( 'theme', $name, $branch, $path, [ 'header' => 'theme', 'at' => $path ] );
					$this->walk( $path, $comp );
				}
			} elseif ( null === $real && $this->linkMatters( $path, $name ) && ! $this->isPhpName( $name ) ) {
				// A theme dir behind a bad link.
				$comp = $this->comp( 'theme', $name, $branch, $path );
				$this->notChecked( $comp, './', 'unreadable' );
			} else {
				$loose[] = $name;
			}
		}
		return $loose;
	}

	/**
	 * Top level of a directory: subdirectories are `directory` components named $prefix . name, files go to $loose.
	 */
	private function scanTop( string $root, array $entries, int $loose, string $prefix ): void {
		foreach ( $entries as $name ) {
			$path = $root . '/' . $name;
			if ( in_array( $name, ANY_SKIPS, true ) ) {
				$this->skipped( $path, $name, $loose );
				continue;
			}
			$real = $this->resolve( $path );

			if ( null !== $real && is_dir( $real ) ) {
				if ( ! $this->inScope( $path, $real ) ) {
					$this->unreadLink( $path, $real, $loose, $this->rel( $loose, $path ) );
				} elseif ( $this->markDir( $real ) ) {
					$comp = $this->comp( 'directory', $prefix . $name, null, $path );
					$this->walk( $path, $comp );
				}
			} elseif ( null === $real && $this->linkMatters( $path, $name ) && ! $this->isPhpName( $name ) ) {
				$comp = $this->comp( 'directory', $prefix . $name, null, $path );
				$this->notChecked( $comp, './', 'unreadable' );
			} else {
				$this->visit( $path, $name, $loose );
			}
		}
	}

	/**
	 * outOfScope(), except that a real directory (not reached through a link) above the scan root is walked:
	 * htdocs may link into the app beside it (`htdocs -> project/app/public`); the root itself stays out.
	 */
	private function inScope( string $path, string $real ): bool {
		return ! $this->outOfScope( $real ) || ( $path === $real && $this->holdsRoot( $real ) );
	}

	/** A directory above the scan root other than the mount itself. */
	private function holdsRoot( string $real ): bool {
		return MOUNT_ROOT !== $real && null !== $this->rootReal && 0 === strpos( $this->rootReal . '/', $real . '/' ) && $this->rootReal !== $real;
	}

	private function walk( string $dir, int $comp ): void {
		$entries = $this->readDir( $dir );
		if ( null === $entries ) {
			$this->notChecked( $comp, $this->rel( $comp, $dir ) . '/', 'unreadable' );
			return;
		}

		foreach ( $entries as $name ) {
			if ( in_array( $name, ANY_SKIPS, true ) ) {
				$this->skipped( $dir . '/' . $name, $this->rel( $comp, $dir . '/' . $name ), $comp );
				continue;
			}
			$this->visit( $dir . '/' . $name, $name, $comp );
		}
	}

	/** One directory entry: recurse into directories, list PHP files. */
	private function visit( string $path, string $name, int $comp ): void {
		$this->tick();
		$real = $this->resolve( $path );

		if ( null === $real ) {
			if ( $this->linkMatters( $path, $name ) ) {
				$this->notChecked( $comp, $this->rel( $comp, $path ), 'unreadable' );
			}
			return;
		}
		if ( ! $this->inScope( $path, $real ) ) {
			$this->unreadLink( $path, $real, $comp, $this->rel( $comp, $path ) );
			return;
		}

		if ( is_dir( $real ) ) {
			if ( $this->markDir( $real ) ) {
				$this->walk( $path, $comp );
			}
			return;
		}

		$st = @stat( $real );
		if ( false === $st || 0100000 !== ( $st['mode'] & 0170000 ) ) {
			return;
		}
		if ( isset( $this->seenFiles[ $st['dev'] ][ $st['ino'] ] ) ) {
			return;
		}
		if ( '.user.ini' === $name ) {
			$this->userIniOnce( $path, $real );
			return;
		}

		// A phar's code is in the archive, which PHPCS can't read (only its `<?php` stub); also behind a code-named link.
		if ( $this->isPharName( $name ) || $this->isPharName( $real ) ) {
			$this->seenFiles[ $st['dev'] ][ $st['ino'] ] = 'phar';
			$this->phar( $comp, $this->rel( $comp, $path ) );
			return;
		}
		$mixed = false;
		if ( ! $this->isPhpName( $name ) && ! $this->isPhpName( $real ) ) {
			// Any name can be included. One PHP can't read can't run either, so it isn't reported.
			$ext = strtolower( (string) pathinfo( $name, PATHINFO_EXTENSION ) );
			if ( in_array( $ext, NO_SNIFF_EXTENSIONS, true ) || in_array( $ext, BACKUP_EXTENSIONS, true ) ) {
				return;
			}
			$tag = $this->sniff( $real );
			if ( null === $tag ) {
				return;
			}
			$mixed = 'mixed' === $tag;
		}
		$this->seenFiles[ $st['dev'] ][ $st['ino'] ] = true;

		if ( ! is_readable( $real ) ) {
			$this->notChecked( $comp, $this->rel( $comp, $path ), 'unreadable' );
			return;
		}

		// Only in skipped dirs: elsewhere one more open per code file would slow every listing for little gain.
		if ( $this->inSkipped && ! $mixed && $this->dataOnly( $real ) ) {
			// Execution stops at the exit: nothing PHPCS could flag runs.
			$c = &$this->comps[ $comp ];
			$c['listed']++;
			$c['files']++;
			$c['bytes'] += $st['size'];
			unset( $c );
			$this->dataFiles++;
			$this->dataBytes += $st['size'];
			$this->manifestChecked( $real, $st );
			return;
		}

		$this->comps[ $comp ]['listed']++;
		$this->listedFiles++;
		$this->listedBytes += $st['size'];
		if ( ( odd_path( $real ) || ! $this->phpcsTakes( $real ) ) && $st['size'] <= STDIN_MAX ) {
			$this->stdinFiles++;
		}
		if ( $this->isScan ) {
			// Relative to the component's base.
			$rel   = $this->rel( $comp, $path );
			$this->listBuf .= pack( 'VPV', $comp, $st['size'], strlen( $rel ) | ( $mixed ? MIXED_FLAG : 0 ) ) . $rel;
			if ( strlen( $this->listBuf ) >= BUFFER_MAX ) {
				$this->flushList();
			}
		}
	}

	/**
	 * A directory searched by name only (uploads/, cache/, node_modules/, ...): only its code-named files are listed (no
	 * sniff), e.g. Wordfence's wflogs/*.php or W3TC's cache files.
	 */
	private function skipped( string $path, string $file, int $comp ): void {
		// A link that dangles or leaves the mount can't be searched (uploads -> /mnt/... included).
		$real = $this->resolve( $path );
		if ( null === $real ) {
			$this->notChecked( $comp, $file . '/', 'unreadable' );
			return;
		}
		if ( ! $this->inScope( $path, $real ) ) {
			$this->unreadLink( $path, $real, $comp, $file );
			return;
		}
		if ( ! is_dir( $path ) ) {
			$this->visit( $path, basename( $path ), $comp );
			return;
		}
		if ( $this->isScan ) {
			$this->skippedDirs[] = $real . '/';
		}
		$this->inSkipped = true;
		foreach ( $this->codeIn( $path ) as $hit => $unlistable ) {
			if ( $unlistable ) {
				$this->notChecked( $comp, $this->rel( $comp, $hit ) . '/', 'unreadable' );
			} else {
				$this->visit( $hit, basename( $hit ), $comp );
			}
		}
		$this->inSkipped = false;
	}

	/**
	 * Code-named and .phar entries of a tree (and bad links that may be code), sorted, each => whether it is a
	 * directory that can't be listed.
	 *
	 * @return array<string,bool>
	 */
	private function codeIn( string $dir ): array {
		$hits  = [];
		$seen  = [];
		$stack = [ $dir ];
		while ( $stack ) {
			$d  = array_pop( $stack );
			$st = @stat( $d );
			if ( false === $st || isset( $seen[ $st['dev'] ][ $st['ino'] ] ) ) {
				continue;
			}
			$seen[ $st['dev'] ][ $st['ino'] ] = true;

			$handle = @opendir( $d );
			if ( false === $handle ) {
				$hits[ $d ] = true;
				continue;
			}
			if ( ! $this->searchable( $d ) ) {
				// Listed but not searchable: nothing in it can be read.
				if ( $this->hasEntries( $handle ) ) {
					$hits[ $d ] = true;
				}
				closedir( $handle );
				continue;
			}
			while ( false !== ( $name = readdir( $handle ) ) ) {
				if ( '.' === $name || '..' === $name ) {
					continue;
				}
				$this->tick();
				$path = $d . '/' . $name;
				// One stat for most entries: only directories and code or extension-less names need more.
				if ( is_dir( $path ) ) {
					$real = $this->resolve( $path );
					if ( null === $real || ( is_link( $path ) && ! $this->inScope( $path, $real ) ) ) {
						$hits[ $path ] = false; // Leaves the mount or the scope: visit() reports it.
					} elseif ( $this->inScope( $path, $real ) ) {
						$stack[] = $path;
					}
					continue;
				}
				$badLink = ! preg_match( '/\.[A-Za-z0-9]{1,8}\z/', $name ) && is_link( $path ) && null === $this->resolve( $path );
				if ( $badLink || $this->isPhpName( $name ) || $this->isPharName( $name ) || '.user.ini' === $name ) {
					$hits[ $path ] = false;
				}
			}
			closedir( $handle );
		}
		ksort( $hits, SORT_STRING );
		return $hits;
	}

	/**
	 * A phar is information unless scanned code names one (decided in finish()). A v3.11.1 call can't show
	 * information, so there it is not_checked at once.
	 */
	private function phar( int $comp, string $rel ): void {
		if ( false === $this->cfg['served'] ) {
			$this->notChecked( $comp, $rel, 'phar' );
			return;
		}
		$this->pharCount++;
		if ( $this->isScan ) {
			$this->append( $this->work . '/phars', $comp . ' ' . base64_encode( $rel ) . "\n" );
		}
	}

	/** Whether a file names `phar://` or `.phar`, in any case. */
	private function namesPhar( string $real ): bool {
		$fh = open_regular( $real );
		if ( null === $fh ) {
			return false;
		}
		$tail  = '';
		$found = false;
		while ( ! $found && '' !== ( $chunk = (string) fread( $fh, 65536 ) ) ) {
			$found = (bool) preg_match( '#phar://|\.phar#i', $tail . $chunk );
			$tail  = substr( $chunk, -6 );
		}
		fclose( $fh );
		return $found;
	}

	/** @return Generator<int,array{0:int,1:string}> The collected phars: component and path relative to it. */
	private function phars(): Generator {
		$fh = $this->pharCount > 0 ? fopen( $this->work . '/phars', 'rb' ) : false;
		while ( false !== $fh && false !== ( $line = fgets( $fh ) ) ) {
			list( $comp, $rel ) = explode( ' ', rtrim( $line, "\n" ) );
			yield [ (int) $comp, (string) base64_decode( $rel ) ];
		}
		if ( false !== $fh ) {
			fclose( $fh );
		}
	}

	/**
	 * A data file PHP never runs past its first statement: `<?php exit; ?>`, `<?php die(); ?>`, `<?php exit('...'); ?>`
	 * (W3TC, WP Super Cache, Wordfence), optionally with `__halt_compiler();` before the `?>`. Without
	 * __halt_compiler() the rest must hold no other open tag, since PHP compiles the whole file first.
	 */
	private function dataOnly( string $path ): bool {
		$fh = open_regular( $path );
		if ( null === $fh ) {
			return false;
		}
		$head = (string) fread( $fh, 512 );
		$ok   = (bool) preg_match( '/\A(?:\xEF\xBB\xBF)?<\?php\s+(?:exit|die)\s*(?:\(\s*(?:\'[^\'\\\\]*\'|"[^"\\\\$]*"|\d+)?\s*\))?\s*;?\s*(__halt_compiler\s*\(\s*\)\s*;?\s*)?\?>/i', $head, $m );
		if ( $ok && empty( $m[1] ) ) {
			$rest = substr( $head, strlen( $m[0] ) );
			while ( true ) {
				if ( preg_match( '/<\?(?:php(?:\s|\z)|=)/i', $rest ) ) {
					$ok = false;
					break;
				}
				$more = fread( $fh, 65536 );
				if ( false === $more || ( '' === $more && ! feof( $fh ) ) ) {
					$ok = false; // A failed read: not known to be data.
					break;
				}
				if ( '' === $more ) {
					break;
				}
				$rest = substr( $rest, -5 ) . $more; // A tag split across reads.
			}
		}
		fclose( $fh );
		return $ok;
	}

	/**
	 * A file without a code name: 'code' when it starts with a PHP open tag (after a BOM, whitespace or a #! line),
	 * 'mixed' when one follows other text in its first SNIFF_BYTES, null otherwise or when it is binary (a NUL byte).
	 */
	private function sniff( string $real ): ?string {
		$fh = open_regular( $real );
		if ( null === $fh ) {
			return null;
		}
		$head = fread( $fh, SNIFF_BYTES );
		fclose( $fh );
		// SNIFF_REGEX is the rule the manifest publishes; the second match only finds where the tag starts.
		if ( false === $head || ! preg_match( SNIFF_REGEX, $head ) || ! preg_match( '/<\?(?:php(?:\s|\z)|=)/i', $head, $m, PREG_OFFSET_CAPTURE ) ) {
			return null;
		}
		return preg_match( '/\A(?:\xEF\xBB\xBF)?(?:#![^\n]*\n)?\s*\z/', substr( $head, 0, $m[0][1] ) ) ? 'code' : 'mixed';
	}

	/** Real path when it exists and stays inside the mount, else null. */
	private function resolve( string $path ): ?string {
		$real = @realpath( $path );
		if ( false === $real || ! $this->inside( $real ) ) {
			return null;
		}
		return $real;
	}

	/**
	 * Targets a link may not pull in: the content root, the scanned directory and
	 * their ancestors, a php site's old releases, and (wp) WordPress core.
	 */
	private function outOfScope( string $real ): bool {
		return null !== $this->scopeWhy( $real );
	}

	/**
	 * Why a real path is out of scope: 'old' (an old release), 'anchor' (the content root, the scanned directory or an
	 * ancestor, walked anyway), 'core' (the live root's core) or 'nested' (another install's core); null when in scope.
	 */
	private function scopeWhy( string $real ): ?string {
		foreach ( $this->oldReleases as $old ) {
			if ( 0 === strpos( $real . '/', $old . '/' ) ) {
				return 'old';
			}
		}
		foreach ( [ $this->contentReal, $this->rootReal ] as $anchor ) {
			if ( null !== $anchor && 0 === strpos( $anchor . '/', $real . '/' ) ) {
				return 'anchor';
			}
		}
		$install = $this->coreOf( $real );
		if ( null === $install ) {
			return null;
		}
		return $install === $this->live ? 'core' : 'nested';
	}

	/**
	 * A link to what the scanner never reads (an old release, the root's core) is not_checked as the link itself: dropping
	 * it would leave code it serves or includes unread. Links to an ancestor are walked through their real path, and
	 * another install's core is its nested_wordpress entry. A link beside `current` to a whole old release is a release
	 * pointer (`previous -> releases/1`), like `current` itself.
	 */
	private function unreadLink( string $path, string $real, int $comp, string $file ): void {
		$why = $this->scopeWhy( $real );
		if ( ! is_link( $path ) || ( 'old' !== $why && 'core' !== $why ) ) {
			return;
		}
		$dir = is_dir( $real );
		if ( 'old' === $why && $dir && in_array( $real, $this->oldReleases, true ) && dirname( $real ) === @realpath( dirname( $path ) ) . '/releases' ) {
			return;
		}
		if ( ! $dir && ! $this->codeLike( basename( $path ), $real ) ) {
			return;
		}
		$at = $this->linkLocation( $path );
		$this->notChecked( $comp, $dir ? rtrim( $file, '/' ) . '/' : $file, 'unreadable', $dir ? $at . '/' : $at );
	}

	/** Real path of a directory entry itself: its directory resolved, the last name kept (a link isn't followed). */
	private function linkLocation( string $path ): string {
		$dir = @realpath( dirname( $path ) );
		return ( false === $dir ? dirname( $path ) : $dir ) . '/' . basename( $path );
	}

	/** A regular file the manifest counts as code: by its name or its target's, or (other names) by the sniff. */
	private function codeLike( string $name, string $real ): bool {
		if ( $this->isPhpName( $name ) || $this->isPharName( $name ) || $this->isPhpName( $real ) || $this->isPharName( $real ) ) {
			return true;
		}
		return ! in_array( strtolower( (string) pathinfo( $name, PATHINFO_EXTENSION ) ), NO_SNIFF_EXTENSIONS, true ) && null !== $this->sniff( $real );
	}

	/**
	 * The install whose core holds a real path: wp-admin/, wp-includes/ (and anything in them) and the core files beside
	 * them, wherever WordPress is installed, on php sites too. Installs other than the live root are recorded.
	 */
	private function coreOf( string $real ): ?string {
		$install = null;
		if ( in_array( basename( $real ), CORE_FILES, true ) && $this->coreDir( dirname( $real ) ) ) {
			$install = dirname( $real );
		} else {
			// A link straight to a file or dir inside core (`-> ../wp-includes/version.php`).
			for ( $p = $real; strlen( $p ) > strlen( MOUNT_ROOT ); $p = dirname( $p ) ) {
				if ( in_array( basename( $p ), CORE_DIRS, true ) && $this->coreDir( dirname( $p ) ) ) {
					$install = dirname( $p );
					break;
				}
			}
		}
		if ( null !== $install && $install !== $this->live ) {
			$this->nested[ $install ] = true;
		}
		return $install;
	}

	/** A directory holding wp-settings.php and wp-includes/. */
	private function coreDir( string $dir ): bool {
		if ( ! isset( $this->coreDirs[ $dir ] ) ) {
			$this->coreDirs[ $dir ] = is_file( $dir . '/wp-settings.php' ) && is_dir( $dir . '/wp-includes' );
		}
		return $this->coreDirs[ $dir ];
	}

	/**
	 * Whether a path that doesn't resolve inside the mount must be reported. What it reaches in the site's php container
	 * (EE's mounts) may differ from what the scanner sees, so only these are left out: names with a never-PHP extension
	 * (`readme.txt`, `style.css`) or `.log`, links to exactly /dev/null, /dev/stdout or /dev/stderr (`error_log -> /dev/stderr`,
	 * as EE accepts them), and targets the scanner sees as neither a file nor a directory.
	 */
	private function linkMatters( string $path, string $name ): bool {
		if ( $this->isPhpName( $name ) || $this->isPharName( $name ) ) {
			return true;
		}
		$target = @realpath( $path );
		if ( false !== $target && is_dir( $target ) ) {
			return true;
		}
		if ( ( false !== $target && ! is_file( $target ) ) || in_array( @readlink( $path ), [ '/dev/null', '/dev/stdout', '/dev/stderr' ], true ) ) {
			return false;
		}
		return ! in_array( strtolower( (string) pathinfo( $name, PATHINFO_EXTENSION ) ), array_merge( NO_SNIFF_EXTENSIONS, [ 'log' ] ), true );
	}

	/** PHP code: a name ending in one of CODE_EXTENSIONS, in any case. */
	private function isPhpName( string $name ): bool {
		return (bool) preg_match( '/\.(?:' . implode( '|', CODE_EXTENSIONS ) . ')\z/i', $name );
	}

	/** `.phar` and the archive forms PHP's phar extension also opens (`.phar.tar`, `.phar.tar.gz`, `.phar.zip`, ...). */
	private function isPharName( string $name ): bool {
		return (bool) preg_match( PHAR_REGEX, $name );
	}

	/** A plugin file name as WordPress reads headers from it: lowercase `.php`. */
	private function isPluginName( string $name ): bool {
		return '.php' === substr( $name, -4 );
	}

	/** Whether PHPCS takes the file by its extension, which it matches case-sensitively. */
	private function phpcsTakes( string $path ): bool {
		return (bool) preg_match( '/\.(?:' . implode( '|', CODE_EXTENSIONS ) . ')\z/', $path );
	}

	private function inside( string $real ): bool {
		foreach ( $this->roots as $root ) {
			if ( $root === $real || 0 === strpos( $real, $root . '/' ) ) {
				return true;
			}
		}
		return false;
	}

	/** Marks a real directory visited; false when it already was (loops, double paths). */
	private function markDir( string $real ): bool {
		$st = @stat( $real );
		if ( false === $st ) {
			return false;
		}
		if ( isset( $this->seenDirs[ $st['dev'] ][ $st['ino'] ] ) ) {
			return false;
		}
		$this->seenDirs[ $st['dev'] ][ $st['ino'] ] = true;
		return true;
	}

	/**
	 * @return string[]|null Entry names, null when the directory can't be listed.
	 * Sorted as if directories had a trailing `/`, so a depth-first walk lists
	 * each component's files in byte order of their full paths.
	 */
	private function readDir( string $dir ): ?array {
		$this->tick();
		$handle = @opendir( $dir );
		if ( false === $handle ) {
			return null;
		}
		$keys = [];
		while ( false !== ( $name = readdir( $handle ) ) ) {
			if ( '.' !== $name && '..' !== $name ) {
				$keys[] = is_dir( $dir . '/' . $name ) ? $name . '/' : $name;
			}
		}
		closedir( $handle );
		// Names without search permission: nothing in it can be read, so the whole directory is reported.
		if ( $keys && ! $this->searchable( $dir ) ) {
			return null;
		}
		sort( $keys, SORT_STRING );
		foreach ( $keys as $i => $key ) {
			if ( '/' === substr( $key, -1 ) ) {
				$keys[ $i ] = substr( $key, 0, -1 );
			}
		}
		return $keys;
	}

	/** Search (x) permission on a directory; posix_access() would drop a trailing `/.`. */
	private function searchable( string $dir ): bool {
		return ! function_exists( 'posix_access' ) || @posix_access( $dir, POSIX_X_OK );
	}

	/** @param resource $handle A directory handle. */
	private function hasEntries( $handle ): bool {
		while ( false !== ( $name = readdir( $handle ) ) ) {
			if ( '.' !== $name && '..' !== $name ) {
				return true;
			}
		}
		return false;
	}

	private function tick(): void {
		if ( 0 === ( ++$this->ticks % 500 ) && microtime( true ) >= $this->listDeadline ) {
			if ( ! $this->isScan ) {
				throw new TimedOut( sprintf( 'too large to estimate in %d s: %d PHP files listed before the time ran out; run the check itself, without --estimate', $this->timeoutLabel, $this->listedFiles + $this->notCheckedCount ) );
			}
			throw new TimedOut( sprintf( 'timed out after %d s while listing files', $this->timeoutLabel ) );
		}
	}

	private function comp( string $type, string $slug, ?string $branch, string $base, array $header = [] ): int {
		$key = $type . "\0" . ( $branch ?? "\0" ) . "\0" . $slug;
		if ( isset( $this->compKeys[ $key ] ) ) {
			return $this->compKeys[ $key ];
		}
		$this->comps[] = [
			'type'     => $type,
			'slug'     => $slug,
			'branch'   => $branch,
			'base'     => $base,
			'header'   => $header,
			'name'     => null,
			'version'  => null,
			'listed'   => 0,
			'files'    => 0,
			'bytes'    => 0,
			'errors'   => 0,
			'warnings' => 0,
		];
		$idx = count( $this->comps ) - 1;

		$this->compKeys[ $key ] = $idx;
		return $idx;
	}

	private function rel( int $comp, string $path ): string {
		$base = $this->comps[ $comp ]['base'];
		if ( $path === $base ) {
			return '.';
		}
		return substr( $path, strlen( $base ) + 1 );
	}

	private function notChecked( int $comp, string $file, string $reason, ?string $manifestPath = null ): void {
		if ( $this->isScan ) {
			$this->spoolNotChecked( $comp, $file, $reason, $manifestPath );
		} else {
			$this->notCheckedCount++;
		}
	}

	/** @return int[] Components with at least one listed file. */
	private function listedComponents(): array {
		$out = [];
		foreach ( $this->comps as $idx => $c ) {
			if ( $c['listed'] > 0 ) {
				$out[] = $idx;
			}
		}
		return $out;
	}

	/** Plugin and theme headers, read while the listing deadline still applies. */
	private function readHeaders(): void {
		foreach ( $this->listedComponents() as $idx ) {
			$header = $this->comps[ $idx ]['header'];
			if ( ! $header ) {
				continue;
			}
			list( $name, $ver ) = $this->readHeader( $header );

			$this->comps[ $idx ]['name']    = $name ?? $this->comps[ $idx ]['slug'];
			$this->comps[ $idx ]['version'] = $ver;
		}
	}

	/** Reads `Plugin Name`/`Theme Name` and `Version` the way WordPress' get_file_data() does. */
	private function readHeader( array $header ): array {
		$field = 'theme' === $header['header'] ? 'Theme Name' : 'Plugin Name';

		if ( 'theme' === $header['header'] ) {
			$candidates = [ $header['at'] . '/style.css' ];
		} elseif ( 'plugin-file' === $header['header'] ) {
			$candidates = [ $header['at'] ];
		} else {
			$candidates = [];
			foreach ( (array) $this->readDir( $header['at'] ) as $n ) {
				if ( $this->isPluginName( $n ) ) {
					$candidates[] = $header['at'] . '/' . $n;
				}
			}
		}

		foreach ( $candidates as $file ) {
			$this->tick();
			$data = read_head( $file );
			if ( null === $data ) {
				continue;
			}
			$data = str_replace( "\r", "\n", $data );
			$name = header_value( $data, $field );
			if ( null !== $name ) {
				return [ $name, header_value( $data, 'Version' ) ];
			}
		}
		return [ null, null ];
	}

	// --------------------------------------------------------------- estimate

	private function estimate(): array {
		$files = $this->listedFiles;
		$bytes = $this->listedBytes;

		$this->work = '/tmp/compat-estimate';
		$this->makeWork();
		try {
			$empty = $this->timed( [ CALIBRATION_DIR . '/empty.php' ] );
			$list  = array_values( array_filter( array_map( 'trim', file( CALIBRATION_DIR . '/sample.list' ) ) ) );
			$calBytes = 0;
			foreach ( $list as $p ) {
				$calBytes += filesize( $p );
			}
			$sample = $this->timed( $list );
		} finally {
			$this->removeWork();
		}

		$calSeconds = max( 0.01, $sample - $empty );
		$bps        = $calBytes / $calSeconds;
		$batches    = $files > 0 ? (int) ceil( $files / $this->cfg['batch_size'] ) : 0;
		$perBatch   = $this->cfg['seconds_per_batch'];
		// Every STDIN file is a PHPCS run of its own, which costs at least its start-up.
		$raw        = $bytes / $bps + $batches * $perBatch + $this->stdinFiles * $empty;
		$est        = max( 1, (int) round( $raw ) );

		$doc = $this->head( 'ok' );

		$doc['php_files']              = $files + $this->notCheckedCount + $this->dataFiles;
		$doc['php_bytes']              = $bytes + $this->dataBytes;
		$doc['components']             = count( $this->listedComponents() );
		$doc['estimated_seconds']      = $est;
		$doc['estimated_seconds_low']  = max( 1, (int) round( $est * $this->cfg['low_factor'] ) );
		$doc['estimated_seconds_high'] = max( 1, (int) ceil( $est * $this->cfg['high_factor'] ) );
		$doc['inputs']                 = [
			'calibration_bytes'   => $calBytes,
			'calibration_seconds' => round( $calSeconds, 2 ),
			'startup_seconds'     => round( $empty, 2 ),
			'bytes_per_second'    => (int) round( $bps ),
			'batches'             => $batches,
			'seconds_per_batch'   => $perBatch,
			'stdin_files'         => $this->stdinFiles,
			'cpus'                => cpu_count(),
			'load_average_1m'     => load_average(),
			'low_factor'          => $this->cfg['low_factor'],
			'high_factor'         => $this->cfg['high_factor'],
		];
		return $doc;
	}

	/** Wall time of one successful PHPCS run over $paths. */
	private function timed( array $paths ): float {
		$t   = hrtime( true );
		$res = $this->phpcs( $paths, $this->cfg['batch_memory'], 'cal' );
		$dt  = ( hrtime( true ) - $t ) / 1e9;
		if ( $res['timeout'] || ( ! $res['ok'] && microtime( true ) >= $this->deadline ) ) {
			throw new TimedOut( sprintf( 'timed out after %d s while calibrating', $this->timeoutLabel ) );
		}
		if ( ! $res['ok'] ) {
			throw new ToolError( 'calibration run failed with exit code ' . $res['rc'] );
		}
		return $dt;
	}

	// ------------------------------------------------------------------- scan

	private function scan(): array {
		$atListing = $this->notCheckedCount;
		rewind( $this->listFh );
		$batch = [];
		$read  = 0;
		while ( null !== ( $rec = $this->nextFile() ) ) {
			$read++;
			$batch[] = $rec;
			if ( count( $batch ) >= $this->cfg['batch_size'] ) {
				$this->runBatch( $batch );
				$batch = [];
			}
		}
		if ( $batch ) {
			$this->runBatch( $batch );
		}
		fclose( $this->listFh );
		$this->listFh = null;
		if ( $read !== $this->listedFiles ) {
			throw new ToolError( 'could not read the file list' );
		}
		// Every listed file ends exactly once: checked, not_checked, or dropped because it is gone.
		$settled = array_sum( array_column( $this->comps, 'files' ) ) + $this->notCheckedCount - $atListing + $this->dropped;
		if ( $settled !== $this->listedFiles + $this->dataFiles ) {
			throw new ToolError( 'internal error: the file counts don\'t add up' );
		}
		$this->checkPins();

		return $this->finish();
	}

	/** @return array{comp:int,size:int,path:string,mixed:bool}|null */
	private function nextFile(): ?array {
		$head = fread( $this->listFh, 16 );
		if ( '' === $head && feof( $this->listFh ) ) {
			return null;
		}
		if ( false === $head || 16 !== strlen( $head ) ) {
			throw new ToolError( 'could not read the file list' );
		}
		$h   = unpack( 'Vcomp/Psize/Vlen', $head );
		$len = $h['len'] & ~MIXED_FLAG;
		$rel = $len > 0 ? fread( $this->listFh, $len ) : '';
		if ( false === $rel || strlen( $rel ) !== $len || ! isset( $this->comps[ $h['comp'] ] ) ) {
			throw new ToolError( 'could not read the file list' );
		}
		return [ 'comp' => $h['comp'], 'size' => $h['size'], 'path' => $this->comps[ $h['comp'] ]['base'] . '/' . $rel, 'mixed' => 0 !== ( $h['len'] & MIXED_FLAG ) ];
	}

	/** Each listed file as it is now: real path, stat, size, PHPCS route and time cap; null real when it is gone. */
	private function prepare( array $batch ): array {
		foreach ( $batch as $k => $f ) {
			$real = $this->resolve( $f['path'] );
			$st   = null === $real ? false : @stat( $real );
			if ( false === $st || 0100000 !== ( $st['mode'] & 0170000 ) ) {
				$batch[ $k ]['real'] = null; // Gone, or no longer a regular file.
				continue;
			}
			// A file rewritten since the listing (a live site) is checked as it is now.
			$batch[ $k ]['size']  = $st['size'];
			$batch[ $k ]['st']    = $st;
			$batch[ $k ]['real']  = $real;
			// --file-list splits on newlines and trims each line, and PHPCS skips a
			// file whose real name has no --extensions match: such files go through STDIN.
			$batch[ $k ]['stdin'] = odd_path( $real ) || ! $this->phpcsTakes( $real );
			// Every file's run has a time cap; a sniffed file (not code by name) gets a shorter one.
			$code               = $this->isPhpName( basename( $f['path'] ) ) || $this->isPhpName( $real );
			$batch[ $k ]['cap'] = (float) ( $code ? $this->cfg['file_timeout'] : $this->cfg['sniffed_timeout'] );
			// Searched only on a site holding a phar, up to the first hit; not in a file refused by size.
			$search = $this->pharCount > 0 && null === $this->pharNamedBy && ! ( $batch[ $k ]['stdin'] && $st['size'] > STDIN_MAX );
			if ( $search && $this->namesPhar( $real ) ) {
				$this->pharNamedBy = $f['path'];
			}
		}
		return $batch;
	}

	/**
	 * Steps 1 and 2: the batch, then on their own the files it didn't finish.
	 * Files are recorded in list order, so findings stay sorted by file.
	 */
	private function runBatch( array $batch ): void {
		$this->checkPins();
		$batch = $this->prepare( $batch );
		foreach ( $this->lint( $batch ) as $k => $result ) {
			$batch[ $k ]['lint'] = $result;
		}

		$plain = [];
		foreach ( $batch as $k => $f ) {
			if ( null !== $f['real'] && ! $f['stdin'] && ! isset( $f['lint'] ) ) {
				$plain[ $f['real'] ] = $k;
			}
		}

		$reader = null;
		if ( $plain ) {
			// Capped at one file's cap: past it, each file runs on its own under its cap, so only a slow file is `timeout`.
			$res = $this->phpcs( array_keys( $plain ), $this->cfg['batch_memory'], 'batch', false, (float) $this->cfg['file_timeout'] );
			$this->debug( sprintf( 'batch %d files rc=%d %.2fs%s', count( $plain ), $res['rc'], $res['seconds'], $res['capped'] ? ' capped' : '' ) );
			if ( $res['timeout'] || ( ! $res['ok'] && microtime( true ) >= $this->deadline ) ) {
				throw $this->timedOutAt( $batch[ reset( $plain ) ]['path'] );
			}
			$this->checkSize( $res );
			if ( $res['ok'] ) {
				$reader = new ReportReader( $res['report'] );
				if ( ! $reader->valid() ) {
					$reader->close();
					$reader = null;
				}
			}
		}

		$remaining = $plain;
		foreach ( $batch as $f ) {
			if ( null === $f['real'] ) {
				// A deleted file can't run; one that can't be reached or is no longer a regular file isn't checked.
				if ( file_exists( $f['path'] ) || is_link( $f['path'] ) || $this->denied( $f['path'] ) ) {
					$this->spoolNotChecked( $f['comp'], $this->rel( $f['comp'], $f['path'] ), 'unreadable' );
				} else {
					$this->dropped++;
				}
				continue;
			}
			if ( isset( $f['lint'] ) ) {
				$this->recordLint( $f );
				continue;
			}
			if ( null !== $reader && ! $f['stdin'] ) {
				// Skip report blocks of files that aren't still expected; a block of a
				// later file means PHPCS didn't report this one.
				while ( null !== ( $name = $reader->peek() ) && $name !== $f['real'] && ! isset( $remaining[ $name ] ) ) {
					$reader->skip();
				}
				unset( $remaining[ $f['real'] ] );
				if ( $name === $f['real'] ) {
					$this->record( $f, $reader );
					continue;
				}
				$this->checkSpace();
			}
			$this->runSingle( $f );
		}

		if ( null !== $reader ) {
			$reader->close();
		}
	}

	/** Steps 2 to 4 for one file. */
	private function runSingle( array $f ): void {
		if ( $f['stdin'] && $f['size'] > STDIN_MAX ) {
			// Refused by size, not copied to /out (real code this large exceeds the retry memory).
			$this->spoolNotChecked( $f['comp'], $this->rel( $f['comp'], $f['path'] ), 'memory' );
			return;
		}
		$last = null;
		foreach ( [ $this->cfg['file_memory'], $this->cfg['retry_memory'] ] as $memory ) {
			$res = $this->phpcs( [ $f['real'] ], $memory, 'single', $f['stdin'], $f['cap'] );
			$this->debug( sprintf( 'single %s at %s rc=%d %.2fs', $f['path'], $memory, $res['rc'], $res['seconds'] ) );
			if ( $res['capped'] ) {
				$this->spoolNotChecked( $f['comp'], $this->rel( $f['comp'], $f['path'] ), 'timeout' );
				return;
			}
			if ( $res['timeout'] || ( ! $res['ok'] && microtime( true ) >= $this->deadline ) ) {
				throw $this->timedOutAt( $f['path'] );
			}
			$this->checkSize( $res );
			if ( $res['unreadable'] ) {
				$this->spoolNotChecked( $f['comp'], $this->rel( $f['comp'], $f['path'] ), 'unreadable' );
				return;
			}
			$last = $res;
			if ( $res['ok'] ) {
				// One input, so the one block is this file, whatever name PHPCS gave it.
				$reader = new ReportReader( $res['report'] );
				if ( ! $reader->valid() ) {
					// A finished run leaves a complete report unless the write failed.
					$reader->close();
					throw new ToolError( 'could not write to the output directory' );
				}
				$found = 1 === $reader->blocks() && null !== $reader->peek();
				if ( $found ) {
					$this->record( $f, $reader );
				}
				$reader->close();
				if ( $found ) {
					return;
				}
				$this->checkSpace();
				break; // Finished without reporting it: more memory won't change that.
			}
		}

		// busybox `timeout` execs PHP, so a SIGKILL from the kernel's OOM killer
		// arrives as 9 rather than 137; the deadline was ruled out above.
		$reason = null !== $last && in_array( $last['rc'], [ 9, 137, 255 ], true ) ? 'memory' : 'error';
		$this->spoolNotChecked( $f['comp'], $this->rel( $f['comp'], $f['path'] ), $reason );
	}

	/** A deploy that re-points `current` (or the content root) mid-scan would mix releases: no verdict then. */
	private function checkPins(): void {
		clearstatcache( true );
		foreach ( $this->pins as $path => $real ) {
			if ( @realpath( $path ) !== $real ) {
				throw new ToolError( 'the site code changed during the scan' );
			}
		}
	}

	/** The deadline is the only bound on a huge site, so the detail says how far the scan got. */
	private function timedOutAt( string $path ): TimedOut {
		$done = array_sum( array_column( $this->comps, 'files' ) );
		$all  = $this->listedFiles + $this->dataFiles;
		$at   = clean_text( $this->relMount( $path ) );
		// No hint to run it again: EE adds its own.
		$text = 'timed out after %d s at %s, with %d of %d files checked';
		return new TimedOut( sprintf( $text, $this->timeoutLabel, $at, $done, $all ) );
	}

	/** A file missing from a finished run on a nearly full disk is a write failure, not `error`. */
	private function checkSpace(): void {
		$free = @disk_free_space( $this->work );
		if ( false !== $free && $free < 1048576 ) {
			throw new ToolError( 'could not write to the output directory' );
		}
	}

	private function checkSize( array $res ): void {
		if ( $res['too_large'] ) {
			throw $this->tooLarge();
		}
	}

	private function tooLarge(): ToolError {
		return new ToolError( sprintf( 'report larger than %d bytes', $this->cfg['report_max'] ) );
	}

	/** A file the lint failed, not run through PHPCS: an ERROR finding, or a not_checked reason. */
	private function recordLint( array $f ): void {
		$rel    = $this->rel( $f['comp'], $f['path'] );
		$reason = $f['lint'];
		if ( is_string( $reason ) ) {
			$this->spoolNotChecked( $f['comp'], $rel, $reason, $f['real'] );
			return;
		}
		list( $line, $text ) = $reason;
		$entry = ',' . json_encode(
			[
				'file'    => clean_text( $rel ),
				'line'    => $line,
				'type'    => 'ERROR',
				'source'  => 'CompatScanner.Syntax.ParseError',
				'message' => clean_text( $text ),
			],
			JSON_FLAGS
		);
		$this->addReportBytes( strlen( $entry ) );
		$this->append( $this->work . "/c{$f['comp']}.e", $entry );
		$this->counted( $f, 1, 0 );
	}

	private function counted( array $f, int $errors, int $warnings ): void {
		$c = &$this->comps[ $f['comp'] ];
		$c['files']++;
		$c['errors']   += $errors;
		$c['warnings'] += $warnings;
		$c['bytes']    += $f['size'];
		unset( $c );
		$this->manifestChecked( $f['real'], $f['st'] );
	}

	/** Counts one finished file and spools its findings from the report block. */
	private function record( array $f, ReportReader $reader ): void {
		$comp = $f['comp'];
		$raw  = $this->rel( $comp, $f['path'] );
		$rel  = clean_text( $raw );

		$block = $reader->take();
		if ( $block['u'] ) {
			$reader->skipMessages();
			$this->spoolNotChecked( $comp, $raw, 'unparseable', $f['real'] );
			return;
		}
		// Text before the tag (a script with `<?php` in a string): an error, or PHPCS's own trouble, may be on code that never runs.
		$messages = null;
		if ( $f['mixed'] ) {
			$messages = [];
			while ( null !== ( $m = $reader->message() ) ) {
				if ( 'ERROR' === $m[2] || 0 === strpos( $m[3], 'Internal.' ) ) {
					$reader->skipMessages();
					$this->spoolNotChecked( $comp, $raw, 'php_tag', $f['real'] );
					return;
				}
				$messages[] = $m;
			}
		}

		$errors = $warnings = $i = 0;
		$buf    = [ 'e' => '', 'w' => '' ];
		while ( null !== ( $m = null !== $messages ? ( $messages[ $i++ ] ?? null ) : $reader->message() ) ) {
			list( $line, , $type, $source, $text ) = $m;
			if ( 0 === strpos( $source, 'Internal.' ) ) {
				continue;
			}
			$entry = ',' . json_encode(
				[ 'file' => $rel, 'line' => $line, 'type' => $type, 'source' => clean_text( $source ), 'message' => clean_text( $text ) ],
				JSON_FLAGS
			);
			$this->addReportBytes( strlen( $entry ) );
			if ( 'ERROR' === $type ) {
				$errors++;
				$key = 'e';
			} else {
				$warnings++;
				$key = 'w';
			}
			$buf[ $key ] .= $entry;
			if ( strlen( $buf[ $key ] ) >= BUFFER_MAX ) {
				$this->append( $this->work . "/c$comp.$key", $buf[ $key ] );
				$buf[ $key ] = '';
			}
		}
		foreach ( $buf as $key => $data ) {
			if ( '' !== $data ) {
				$this->append( $this->work . "/c$comp.$key", $data );
			}
		}

		$this->counted( $f, $errors, $warnings );
	}

	/** @param string|null $manifestPath What the manifest lists, when it isn't the component's base plus `$file`. */
	private function spoolNotChecked( int $comp, string $file, string $reason, ?string $manifestPath = null ): void {
		$c     = $this->comps[ $comp ];
		$entry = ',' . json_encode(
			[ 'type' => $c['type'], 'slug' => clean_text( $c['slug'] ), 'branch' => clean_nullable( $c['branch'] ), 'file' => clean_text( $file ), 'reason' => $reason ],
			JSON_FLAGS
		);
		$this->addReportBytes( strlen( $entry ) );
		$this->append( $this->work . '/not_checked', $entry );
		$this->notCheckedCount++;
		if ( ! $this->cfg['manifest'] ) {
			return;
		}

		// The manifest names it by real path; a directory (`…/`) covers everything below it.
		$dir  = '/' === substr( $file, -1 );
		$rel  = rtrim( $file, '/' );
		$path = '' === $rel || '.' === $rel ? $c['base'] : $c['base'] . '/' . $rel;
		$real = @realpath( $path );
		$path = false !== $real && $this->inside( $real ) ? $real : $path;
		$path = $dir ? rtrim( $path, '/' ) . '/' : $path;
		// One per report entry, so a path may repeat; a set would grow with every entry.
		$this->manifestAdd( 'not_checked', $manifestPath ?? $path );
	}

	/** A file counted as checked, once per inode (hard links and two routes to one file). */
	private function manifestChecked( string $real, array $st ): void {
		if ( ! $this->cfg['manifest'] || 'm' === ( $this->seenFiles[ $st['dev'] ][ $st['ino'] ] ?? null ) ) {
			return;
		}
		$this->seenFiles[ $st['dev'] ][ $st['ino'] ] = 'm';
		$this->manifestAdd( 'checked', $real );
	}

	private function manifestAdd( string $list, string $path ): void {
		$this->manBuf[ $list ] .= ',' . json_encode( manifest_path( $path ), JSON_FLAGS );
		if ( strlen( $this->manBuf[ $list ] ) >= BUFFER_MAX ) {
			$this->append( $this->work . "/m-$list", $this->manBuf[ $list ] );
			$this->manBuf[ $list ] = '';
		}
	}

	/** /out/manifest.json (COMPAT_MANIFEST=1, for tests): what the scan covered, by real path, with the rules to re-derive the code files. */
	private function writeManifest(): void {
		foreach ( $this->manBuf as $list => $data ) {
			if ( '' !== $data ) {
				$this->append( $this->work . "/m-$list", $data );
			}
		}
		$core = array_merge( null === $this->live ? [] : [ $this->live ], $this->leftOut );
		$head = [
			'v'                           => 1,
			'code_extensions'             => CODE_EXTENSIONS,
			'extensions_case_insensitive' => true,
			'phar_regex'                  => PHAR_REGEX,
			'sniff'                       => [
				'bytes'              => SNIFF_BYTES,
				'regex'              => SNIFF_REGEX,
				'exclude_extensions' => array_merge( NO_SNIFF_EXTENSIONS, BACKUP_EXTENSIONS ),
				'scope'              => 'except_skipped_dirs',
				'skipped_dirs'       => array_values( array_unique( array_map( 'manifest_path', $this->skippedDirs ) ) ),
			],
			'roots'                       => array_map( 'manifest_dir', $this->roots ),
			'excluded'                    => [],
			'old_releases'                => array_map( 'manifest_dir', $this->oldReleases ),
			'core'                        => [ 'roots' => array_map( 'manifest_dir', $core ), 'dirs' => CORE_DIRS, 'files' => CORE_FILES ],
		];

		$tmp = OUT_DIR . '/manifest.json.tmp';
		$out = @fopen( $tmp, 'wb' );
		if ( false === $out ) {
			throw new ToolError( 'output directory not writable' );
		}
		$write = static function ( string $data ) use ( $out ) {
			if ( fwrite( $out, $data ) !== strlen( $data ) ) {
				throw new ToolError( 'could not write the file manifest' );
			}
		};
		try {
			$json = json_encode( $head, JSON_FLAGS );
			$write( substr( $json, 0, -1 ) . ',"checked":[' );
			$first = true;
			$this->copySpool( $this->work . '/m-checked', $write, $first );
			$write( '],"not_checked":[' );
			$first = true;
			$this->copySpool( $this->work . '/m-not_checked', $write, $first );
			$write( '],"information":[' );
			$first = true;
			$this->copySpool( $this->work . '/m-information', $write, $first );
			$write( "]}\n" );
		} catch ( Throwable $e ) {
			fclose( $out );
			@unlink( $tmp );
			throw $e;
		}
		if ( ! fclose( $out ) || ! @rename( $tmp, OUT_DIR . '/manifest.json' ) ) {
			@unlink( $tmp );
			throw new ToolError( 'could not write the file manifest' );
		}
	}

	private function addReportBytes( int $n ): void {
		$this->reportBytes += $n;
		if ( $this->reportBytes > $this->cfg['report_max'] ) {
			throw $this->tooLarge();
		}
	}

	/** Builds the summary and streams the report from the spool. */
	private function finish(): array {
		$this->settlePhars();
		$listed = $this->listedComponents();

		$errors = $warnings = $checked = $bytes = $withErrors = 0;
		foreach ( $listed as $idx ) {
			$c         = $this->comps[ $idx ];
			$errors   += $c['errors'];
			$warnings += $c['warnings'];
			$checked  += $c['files'];
			$bytes    += $c['bytes'];
			if ( $c['errors'] > 0 ) {
				$withErrors++;
			}
		}

		if ( $errors > 0 ) {
			$verdict = false;
		} elseif ( $this->notCheckedCount > 0 ) {
			$verdict = null;
		} else {
			$verdict = true;
		}

		$doc = $this->head( 'ok' );

		$doc['safe_to_upgrade']        = $verdict;
		$doc['errors']                 = $errors;
		$doc['warnings']               = $warnings;
		$doc['files_checked']          = $checked;
		$doc['files_not_checked']      = $this->notCheckedCount;
		$doc['php_bytes']              = $bytes;
		$doc['components_checked']     = count( $listed );
		$doc['components_with_errors'] = $withErrors;
		$doc['duration_s']             = (int) round( microtime( true ) - $this->start );
		$doc['tool']                   = tool_versions( $this->cfg['image'] );

		$comps = $this->comps;
		usort(
			$listed,
			static function ( $a, $b ) use ( $comps ) {
				$x = $comps[ $a ];
				$y = $comps[ $b ];
				return [ $y['errors'], $y['warnings'], TYPE_ORDER[ $x['type'] ], null !== $x['branch'], (string) $x['branch'], $x['slug'] ]
					<=> [ $x['errors'], $x['warnings'], TYPE_ORDER[ $y['type'] ], null !== $y['branch'], (string) $y['branch'], $y['slug'] ];
			}
		);

		if ( $this->cfg['manifest'] ) {
			$this->writeManifest();
		}
		$this->writeReport( $doc, $listed );
		$this->removeWork();
		$this->debug( sprintf( 'entrypoint peak memory %d bytes', memory_get_peak_usage() ) );
		return $doc;
	}

	private function writeReport( array $summary, array $order ): void {
		$tmp = OUT_DIR . '/report.json.tmp';
		$out = @fopen( $tmp, 'wb' );
		if ( false === $out ) {
			throw new ToolError( 'output directory not writable' );
		}

		$written = 0;
		$write   = function ( string $data ) use ( $out, &$written ) {
			$written += strlen( $data );
			if ( $written > $this->cfg['report_max'] ) {
				throw $this->tooLarge();
			}
			if ( fwrite( $out, $data ) !== strlen( $data ) ) {
				throw new ToolError( 'could not write the report' );
			}
		};

		try {
			$head = json_encode( $summary, JSON_FLAGS );
			$write( substr( $head, 0, -1 ) . ',"components":[' );

			foreach ( $order as $n => $idx ) {
				$c    = $this->comps[ $idx ];
				$meta = json_encode(
					[
						'type'     => $c['type'],
						'slug'     => clean_text( $c['slug'] ),
						'branch'   => clean_nullable( $c['branch'] ),
						'name'     => clean_nullable( $c['name'] ),
						'version'  => clean_nullable( $c['version'] ),
						'files'    => $c['files'],
						'errors'   => $c['errors'],
						'warnings' => $c['warnings'],
					],
					JSON_FLAGS
				);
				$write( ( $n ? ',' : '' ) . substr( $meta, 0, -1 ) . ',"findings":[' );
				$first = true;
				foreach ( [ "c$idx.e", "c$idx.w" ] as $spool ) {
					$this->copySpool( $this->work . '/' . $spool, $write, $first );
				}
				$write( ']}' );
			}

			$write( '],"not_checked":[' );
			$first = true;
			$this->copySpool( $this->work . '/not_checked', $write, $first );
			$write( '],' . substr( json_encode( $this->reportTail(), JSON_FLAGS ), 1, -1 ) );
			if ( false !== $this->cfg['served'] ) {
				$this->writePhars( $write );
			}
			$write( "}\n" );
		} catch ( Throwable $e ) {
			fclose( $out );
			@unlink( $tmp );
			throw $e;
		}

		if ( ! fclose( $out ) || ! @rename( $tmp, OUT_DIR . '/report.json' ) ) {
			throw new ToolError( 'could not write the report' );
		}
	}

	/** Report keys after not_checked: the WordPress installs and, for a caller that sets COMPAT_SERVED, the old releases left out. */
	private function reportTail(): array {
		$tail = [ 'wordpress_installs' => [] ];
		foreach ( $this->installs as $i ) {
			$tail['wordpress_installs'][] = [ 'dir' => clean_text( $i['dir'] ), 'version' => clean_text( $i['version'] ), 'live' => $i['live'] ];
		}
		if ( false !== $this->cfg['served'] ) {
			$tail['excluded_old_releases'] = array_map( 'clean_text', $this->oldReleases );
		}
		return $tail;
	}

	/** With a phar named by scanned code, every phar is not_checked; else the manifest lists each as information. */
	private function settlePhars(): void {
		foreach ( $this->phars() as list( $comp, $rel ) ) {
			if ( null !== $this->pharNamedBy ) {
				$this->spoolNotChecked( $comp, $rel, 'phar' );
			} elseif ( $this->cfg['manifest'] ) {
				$this->manifestAdd( 'information', (string) realpath( $this->comps[ $comp ]['base'] . '/' . $rel ) );
			}
		}
	}

	/** `phars` (the phars kept as information, streamed: a site may hold thousands) and `phar_named_by`. */
	private function writePhars( callable $write ): void {
		$write( ',"phars":[' );
		$sep = '';
		foreach ( null === $this->pharNamedBy ? $this->phars() : [] as list( $comp, $rel ) ) {
			$write( $sep . json_encode( clean_text( $this->comps[ $comp ]['base'] . '/' . $rel ), JSON_FLAGS ) );
			$sep = ',';
		}
		$write( '],"phar_named_by":' . json_encode( clean_nullable( $this->pharNamedBy ), JSON_FLAGS ) );
	}

	/** Appends a spool of `,{...}` items, dropping the leading comma of the first; then deletes it. */
	private function copySpool( string $file, callable $write, bool &$first ): void {
		if ( ! is_file( $file ) ) {
			return;
		}
		$in = fopen( $file, 'rb' );
		if ( false === $in ) {
			throw new ToolError( 'could not read the spool' );
		}
		if ( $first ) {
			fread( $in, 1 );
			$first = false;
		}
		while ( ! feof( $in ) ) {
			$chunk = fread( $in, BUFFER_MAX );
			if ( false === $chunk ) {
				throw new ToolError( 'could not read the spool' );
			}
			if ( '' !== $chunk ) {
				$write( $chunk );
			}
		}
		fclose( $in );
		@unlink( $file );
	}

	// ------------------------------------------------------------------ phpcs

	/**
	 * One PHPCS run under `timeout -s KILL` with the time left.
	 *
	 * @return array{ok:bool,timeout:bool,too_large:bool,unreadable:bool,rc:int,seconds:float,report:string}
	 */
	private function phpcs( array $paths, string $memory, string $tag, bool $stdin = false, float $cap = 0.0 ): array {
		$report = $this->work . "/phpcs-$tag.out";
		$res    = [ 'ok' => false, 'timeout' => false, 'capped' => false, 'too_large' => false, 'unreadable' => false, 'rc' => -1, 'seconds' => 0.0, 'report' => $report ];

		$in = [ 'file', '/dev/null', 'r' ];
		if ( $stdin ) {
			// Before the time left is taken, so the copy can't push the run past the deadline.
			$in = $this->stdinCopy( $paths[0] );
			if ( null === $in ) {
				$res['unreadable'] = true;
				return $res;
			}
		}
		@unlink( $report );

		$cmd = [
			PHP_BINARY, '-d', 'memory_limit=' . $memory, '-d', 'display_errors=stderr', '-d', 'log_errors=0',
			PHPCS_BIN,
			'--standard=' . ( 'php' === $this->cfg['site_type'] ? 'PHPCompatibility' : 'PHPCompatibilityWP' ) . ',' . SNIFFS_DIR,
			'--runtime-set', 'testVersion', $this->cfg['version'],
			'--extensions=' . implode( ',', CODE_EXTENSIONS ), '--no-cache', '-q', '--no-colors', '--ignore-annotations',
			'--report=' . REPORT_CLASS, '--report-file=' . $report,
		];

		if ( $stdin ) {
			// PHPCS resolves --stdin-path and filters it by extension, so it must end in one it takes.
			$cmd[] = '--stdin-path=' . $paths[0] . ( $this->phpcsTakes( $paths[0] ) ? '' : '.php' );
			$cmd[] = '-';
		} else {
			$list = $this->work . '/phpcs.list';
			$this->put( $list, implode( "\n", $paths ) . "\n" );
			$cmd[] = '--file-list=' . $list;
		}

		$err = $this->cfg['debug'] ? STDERR : [ 'file', '/dev/null', 'w' ];
		// Bounds what PHPCS can write (SIGXFSZ past the limit).
		$fsize = $this->cfg['report_max'] + max( FSIZE_SLACK, count( $paths ) * HEADER_MAX );
		$res   = array_merge( $res, $this->runTimed( $cmd, $cap, [ 0 => $in, 1 => [ 'file', '/dev/null', 'w' ], 2 => $err ], $fsize ) );
		if ( is_resource( $in ) ) {
			fclose( $in );
			@unlink( $this->work . '/stdin' );
		}
		if ( $res['capped'] || $res['timeout'] ) {
			return $res;
		}

		clearstatcache();
		$size = @filesize( $report );
		if ( false !== $size && $size >= $fsize ) {
			$res['too_large'] = true;
		} elseif ( $res['rc'] >= 0 && $res['rc'] <= 3 && false !== $size ) {
			$res['ok'] = true;
		}
		return $res;
	}

	/**
	 * Runs a command under `timeout -s KILL` with the time left, at most $cap seconds when $cap > 0.
	 *
	 * @return array{rc:int,seconds:float,capped:bool,timeout:bool} capped: killed by $cap; timeout: no time was left.
	 */
	private function runTimed( array $cmd, float $cap, array $spec, int $fsize = 0 ): array {
		$res  = [ 'rc' => -1, 'seconds' => 0.0, 'capped' => false, 'timeout' => false ];
		$left = $this->deadline - microtime( true );
		if ( $left <= 0 ) {
			$res['timeout'] = true;
			return $res;
		}
		$capped = $cap > 0 && $cap < $left;
		// The exact time left (busybox takes fractions), so no run finishes past the deadline.
		$limit = sprintf( '%.3F', ceil( ( $capped ? $cap : $left ) * 1000 ) / 1000 );
		$t     = hrtime( true );
		// Set only around the fork, so the entrypoint's own writes aren't bound by it.
		set_fsize( $fsize > 0 ? $fsize : null );
		$proc = proc_open( array_merge( [ 'timeout', '-s', 'KILL', $limit ], $cmd ), $spec, $pipes );
		set_fsize( null );
		if ( ! is_resource( $proc ) ) {
			throw new ToolError( 'could not start ' . basename( end( $cmd ) ) );
		}
		$res['rc']      = proc_close( $proc );
		$res['seconds'] = ( hrtime( true ) - $t ) / 1e9;
		// Killed by its own cap, not the scan deadline (busybox timeout reports SIGKILL as 9 or 137).
		$res['capped'] = $capped && in_array( $res['rc'], [ 9, 137 ], true ) && $res['seconds'] >= $cap * 0.99;
		return $res;
	}

	/**
	 * `php -l` over a batch, then each file on its own when it fails: PHPCompatibility misses some parse errors (`#[`
	 * before PHP 8, an unclosed final comment). Not for targets before 8.0, whose syntax PHP 8.4 rejects, nor for files
	 * with text before their tag (a script or shell history quoting `<?php`), which PHPCS alone checks.
	 *
	 * @return array<int,array{0:int,1:string}|string> By batch key, the files that fail: [ line, message ] or a not_checked reason.
	 */
	private function lint( array $batch ): array {
		$paths = [];
		foreach ( $batch as $k => $f ) {
			if ( null !== $f['real'] && ! $f['mixed'] ) {
				$paths[ $k ] = $f['real'];
			}
		}
		if ( ! $paths || version_compare( $this->cfg['version'], '8.0', '<' ) ) {
			return [];
		}
		$res = $this->lintRun( array_values( $paths ), (float) $this->cfg['file_timeout'] );
		if ( 0 === $res['rc'] ) {
			return [];
		}
		$failed = [];
		foreach ( $paths as $k => $real ) {
			$res = $this->lintRun( [ $real ], $batch[ $k ]['cap'] );
			if ( $res['timeout'] ) {
				throw $this->timedOutAt( $batch[ $k ]['path'] );
			}
			$result = 0 === $res['rc'] ? null : $this->lintResult( $res, $real );
			if ( null !== $result ) {
				$failed[ $k ] = $result;
			}
		}
		return $failed;
	}

	private function lintRun( array $paths, float $cap ): array {
		$err  = $this->work . '/lint.err';
		$args = [ '-d', 'memory_limit=' . $this->cfg['retry_memory'], '-d', 'display_errors=stderr', '-d', 'log_errors=0' ];
		// EE's php images turn short tags off; on, PHP would parse a template's `<?xml` as code.
		$cmd = array_merge( [ PHP_BINARY, '-d', 'short_open_tag=0' ], $args, [ '-l' ], $paths );
		$res = $this->runTimed( $cmd, $cap, [ 0 => [ 'file', '/dev/null', 'r' ], 1 => [ 'file', '/dev/null', 'w' ], 2 => [ 'file', $err, 'w' ] ] );

		$res['stderr'] = (string) file_get_contents( $err, false, null, 0, 65536 );
		return $res;
	}

	/**
	 * @return array{0:int,1:string}|string|null The finding, `unparseable` for a target newer than this PHP, which can't
	 *                                           parse its syntax, or null when only this PHP's own functions clash.
	 */
	private function lintResult( array $res, string $real ) {
		if ( $res['capped'] ) {
			return 'timeout';
		}
		if ( in_array( $res['rc'], [ 9, 137 ], true ) || false !== strpos( $res['stderr'], 'Allowed memory size' ) ) {
			return 'memory';
		}
		if ( 255 !== $res['rc'] ) {
			return 'error';
		}
		$text = trim( str_replace( ' in ' . $real, '', $res['stderr'] ) );
		// A redeclared function parsed, so it is a finding on any target, unless it clashes only with a function PHP added
		// after the target (PHPCS still checks the file then).
		if ( preg_match( '/^Fatal error: Cannot redeclare (?:function )?(\w+)\(\)(.*)$/s', $text, $m ) ) {
			$native = 0 === strpos( $m[2], ' on line ' );
			$since  = $native ? ( native_since()[ strtolower( $m[1] ) ] ?? null ) : null;
			if ( null !== $since && version_compare( $this->cfg['version'], $since, '<' ) ) {
				return null;
			}
		} elseif ( version_compare( $this->cfg['version'], PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION, '>' ) ) {
			return 'unparseable';
		}
		preg_match( '/^(.*?)(?: on line (\d+))?$/s', $text, $m );
		return [ (int) ( $m[2] ?? 0 ), $m[1] ];
	}

	/**
	 * STDIN for PHPCS: a copy behind our own `phpcs_input_file:` line, which PHPCS drops instead of the file's first line.
	 * A constant name, as a path may hold an end of line. A file, not a pipe: PHPCS stops reading after 200 ms without data.
	 *
	 * @return resource|null Rewound copy, or null when the file can't be read.
	 */
	private function stdinCopy( string $path ) {
		$src = open_regular( $path );
		if ( null === $src ) {
			return null;
		}
		$dst = @fopen( $this->work . '/stdin', 'w+b' );
		if ( false === $dst ) {
			fclose( $src );
			throw new ToolError( 'could not write to the output directory' );
		}
		$data = "phpcs_input_file: STDIN\n";
		do {
			if ( microtime( true ) >= $this->deadline ) {
				fclose( $src );
				fclose( $dst );
				@unlink( $this->work . '/stdin' );
				throw $this->timedOutAt( $path );
			}
			if ( fwrite( $dst, $data ) !== strlen( $data ) ) {
				fclose( $src );
				fclose( $dst );
				throw new ToolError( 'could not write to the output directory' );
			}
			$data = fread( $src, BUFFER_MAX );
		} while ( false !== $data && '' !== $data );
		$failed = false === $data || ! feof( $src );
		fclose( $src );
		if ( $failed ) {
			fclose( $dst );
			@unlink( $this->work . '/stdin' );
			return null;
		}
		rewind( $dst );
		return $dst;
	}

	// ------------------------------------------------------------------ misc

	/** Appends to a work file; a short write (full disk) is a tool error. */
	private function append( string $file, string $data ): void {
		if ( @file_put_contents( $file, $data, FILE_APPEND ) !== strlen( $data ) ) {
			throw new ToolError( 'could not write to the output directory' );
		}
	}

	private function put( string $file, string $data ): void {
		if ( @file_put_contents( $file, $data ) !== strlen( $data ) ) {
			throw new ToolError( 'could not write to the output directory' );
		}
	}

	private function flushList(): void {
		if ( '' === $this->listBuf ) {
			return;
		}
		if ( fwrite( $this->listFh, $this->listBuf ) !== strlen( $this->listBuf ) ) {
			throw new ToolError( 'could not write to the output directory' );
		}
		$this->listBuf = '';
	}

	private function makeWork(): void {
		$this->removeWork();
		if ( ! @mkdir( $this->work, 0700 ) ) {
			throw new ToolError( 'output directory not writable' );
		}
	}

	public function removeWork(): void {
		if ( is_resource( $this->listFh ) ) {
			fclose( $this->listFh );
			$this->listFh = null;
		}
		if ( '' === $this->work || ! is_dir( $this->work ) ) {
			return;
		}
		foreach ( (array) scandir( $this->work ) as $f ) {
			if ( '.' !== $f && '..' !== $f ) {
				@unlink( $this->work . '/' . $f );
			}
		}
		@rmdir( $this->work );
	}

	public function head( string $status ): array {
		return doc_head( $this->cfg, $status );
	}

	public function reduced( string $status ): array {
		$doc = $this->head( $status );

		$doc['safe_to_upgrade'] = null;
		return $doc;
	}

	private function debug( string $msg ): void {
		if ( $this->cfg['debug'] ) {
			fwrite( STDERR, sprintf( "[%7.2f] %s\n", microtime( true ) - $this->start, $msg ) );
		}
	}
}

/**
 * Streams a LinesReport file: validate() first, then peek()/take() each file's
 * header and read its messages with message(), all in report order.
 */
final class ReportReader {

	/** @var resource|null */
	private $fh;
	/** @var bool */
	private $valid = false;
	/** @var int */
	private $blocks = 0;
	/** @var array|null Header of the next block, read ahead. */
	private $next;
	/** @var int Messages of the taken block still unread. */
	private $pending = 0;
	/** @var bool A line without its newline was read (truncated file). */
	private $broken = false;

	public function __construct( string $file ) {
		$fh = @fopen( $file, 'rb' );
		if ( false === $fh ) {
			return;
		}
		$this->fh = $fh;
		// PHPCS ends even an empty report with a newline; zero bytes is a failed write.
		$st = fstat( $fh );
		if ( false !== $st && $st['size'] > 0 && $this->validate() ) {
			$this->valid = true;
			rewind( $this->fh );
			$this->next = $this->header();
		}
	}

	public function valid(): bool {
		return $this->valid;
	}

	public function blocks(): int {
		return $this->blocks;
	}

	/** Real file name of the next block, or null at the end. */
	public function peek(): ?string {
		$this->skipMessages();
		return null === $this->next ? null : $this->next['f'];
	}

	/** @return array{f:string,n:int,u:int} */
	public function take(): array {
		$this->skipMessages();
		$block         = $this->next;
		$this->pending = $block['n'];
		$this->next    = null;
		return $block;
	}

	public function skip(): void {
		$this->take();
		$this->skipMessages();
	}

	/** Next message of the taken block, or null when it has none left. */
	public function message(): ?array {
		if ( $this->pending <= 0 ) {
			return null;
		}
		$this->pending--;
		$m = $this->decode( $this->line() );
		if ( 0 === $this->pending ) {
			$this->next = $this->header();
		}
		return $m;
	}

	public function skipMessages(): void {
		while ( $this->pending > 0 ) {
			$this->pending--;
			$this->line();
		}
		if ( null === $this->next && null !== $this->fh && ! feof( $this->fh ) ) {
			$this->next = $this->header();
		}
	}

	public function close(): void {
		if ( null !== $this->fh ) {
			fclose( $this->fh );
			$this->fh = null;
		}
	}

	/** Checks the whole file: every header is followed by exactly its count of message lines. */
	private function validate(): bool {
		while ( true ) {
			$line = $this->line();
			if ( null === $line ) {
				return ! $this->broken;
			}
			if ( '' === $line ) {
				continue;
			}
			$h = $this->parseHeader( $line );
			if ( null === $h ) {
				return false;
			}
			$this->blocks++;
			for ( $i = 0; $i < $h['n']; $i++ ) {
				if ( null === $this->decode( $this->line() ) ) {
					return false;
				}
			}
		}
	}

	private function header(): ?array {
		while ( null !== ( $line = $this->line() ) ) {
			if ( '' !== $line ) {
				return $this->parseHeader( $line );
			}
		}
		return null;
	}

	private function parseHeader( string $line ): ?array {
		$h = json_decode( $line, true, 4 );
		if ( ! is_array( $h ) || ! isset( $h['f'], $h['n'], $h['u'] ) || ! is_string( $h['f'] ) || ! is_int( $h['n'] ) || $h['n'] < 0 ) {
			return null;
		}
		$name = base64_decode( $h['f'], true );
		if ( false === $name ) {
			return null;
		}
		return [ 'f' => $name, 'n' => $h['n'], 'u' => $h['u'] ? 1 : 0 ];
	}

	private function decode( ?string $line ): ?array {
		if ( null === $line ) {
			return null;
		}
		$m = json_decode( $line, true, 4, JSON_INVALID_UTF8_SUBSTITUTE );
		if ( ! is_array( $m ) || 5 !== count( $m ) || ! is_int( $m[0] ) || ! is_string( $m[2] ) || ! is_string( $m[3] ) || ! is_string( $m[4] ) ) {
			return null;
		}
		return $m;
	}

	/** One line without its newline; null at EOF, on a truncated or overlong line. */
	private function line(): ?string {
		if ( null === $this->fh ) {
			return null;
		}
		$line = fgets( $this->fh, LINE_MAX + 1 );
		if ( false === $line ) {
			return null;
		}
		if ( "\n" !== substr( $line, -1 ) ) {
			$this->broken = true;
			return null;
		}
		return substr( $line, 0, -1 );
	}
}

// -------------------------------------------------------------------- helpers

function doc_head( array $cfg, string $status ): array {
	$doc = [ 'v' => 1, 'status' => $status ];
	if ( 'estimate' === ( $cfg['mode'] ?? '' ) ) {
		$doc['estimate'] = true;
	}
	if ( '' !== $cfg['site'] ) {
		$doc['site'] = $cfg['site'];
	}
	$doc['target'] = $cfg['version'];
	if ( 'estimate' !== ( $cfg['mode'] ?? '' ) || 'ok' !== $status ) {
		$doc['safe_to_upgrade'] = null;
	}
	return $doc;
}

/**
 * Text from the site (paths, headers, messages) made safe to print: invalid
 * UTF-8, control, bidi and zero-width characters each become U+FFFD.
 */
function clean_text( string $s ): string {
	if ( ! mb_check_encoding( $s, 'UTF-8' ) ) {
		$s = (string) json_decode( (string) json_encode( $s, JSON_INVALID_UTF8_SUBSTITUTE ) );
	}
	return (string) preg_replace( '/[\x{00}-\x{1F}\x{7F}-\x{9F}\x{061C}\x{200B}-\x{200F}\x{2028}-\x{202E}\x{2060}-\x{2069}\x{FEFF}]/u', "\u{FFFD}", $s );
}

/** A manifest path: JSON can't carry the bytes of one that isn't UTF-8, so it goes as `b64:` + base64 (paths start with `/`). */
function manifest_path( string $path ): string {
	return preg_match( '//u', $path ) ? $path : 'b64:' . base64_encode( $path );
}

function manifest_dir( string $dir ): string {
	return manifest_path( $dir . '/' );
}

/** An ini value as PHP reads it: quoted, or up to a `;` comment; none, off, no, false and null are empty. */
function ini_value( string $raw ): string {
	$raw = trim( $raw );
	if ( preg_match( '/^"([^"]*)"|^\'([^\']*)\'/', $raw, $m ) ) {
		return $m[1] . ( $m[2] ?? '' );
	}
	$value = trim( (string) strstr( $raw . ';', ';', true ) );
	return preg_match( '/^(?:none|off|no|false|null)?\z/i', $value ) ? '' : $value;
}

function clean_nullable( ?string $s ): ?string {
	return null === $s ? null : clean_text( $s );
}

/**
 * Opens a site file only when it is a regular file; non-blocking, so a FIFO
 * can't hang the entrypoint.
 *
 * @return resource|null
 */
function open_regular( string $path ) {
	$fh = @fopen( $path, 'rbn' );
	if ( false === $fh ) {
		return null;
	}
	$st = fstat( $fh );
	if ( false === $st || 0100000 !== ( $st['mode'] & 0170000 ) ) {
		fclose( $fh );
		return null;
	}
	return $fh;
}

/** First 8 KB of a regular file inside the mount, or null. */
function read_head( string $path ): ?string {
	$real = @realpath( $path );
	if ( false === $real || ( MOUNT_ROOT !== $real && 0 !== strpos( $real, MOUNT_ROOT . '/' ) ) ) {
		return null;
	}
	$fh = open_regular( $real );
	if ( null === $fh ) {
		return null;
	}
	$data = fread( $fh, 8192 );
	fclose( $fh );
	return false === $data ? null : $data;
}

function header_value( string $data, string $field ): ?string {
	if ( preg_match( '/^(?:[ \t]*<\?php)?[ \t\/*#@]*' . preg_quote( $field, '/' ) . ':(.*)$/mi', $data, $m ) ) {
		$value = trim( preg_replace( '/\s*(?:\*\/|\?>).*/', '', $m[1] ) );
		if ( '' !== $value ) {
			return $value;
		}
	}
	return null;
}

/** Sets the soft file size limit that children inherit; null restores the original. */
function set_fsize( ?int $bytes ): void {
	static $orig = null;
	if ( ! function_exists( 'posix_setrlimit' ) ) {
		return;
	}
	if ( null === $orig ) {
		$lim  = posix_getrlimit();
		$orig = [ $lim['soft filesize'] ?? 'unlimited', $lim['hard filesize'] ?? 'unlimited' ];
		$orig = array_map(
			static function ( $v ) {
				return 'unlimited' === $v ? POSIX_RLIMIT_INFINITY : (int) $v;
			},
			$orig
		);
	}
	$soft = null === $bytes ? $orig[0] : $bytes;
	if ( POSIX_RLIMIT_INFINITY !== $orig[1] && ( POSIX_RLIMIT_INFINITY === $soft || $soft > $orig[1] ) ) {
		$soft = $orig[1];
	}
	@posix_setrlimit( POSIX_RLIMIT_FSIZE, $soft, $orig[1] );
}

function tool_versions( string $image ): array {
	$out  = [ 'phpcs' => null, 'phpcompatibility' => null, 'phpcompatibility_wp' => null ];
	$map  = [
		'squizlabs/php_codesniffer'            => 'phpcs',
		'phpcompatibility/php-compatibility'   => 'phpcompatibility',
		'phpcompatibility/phpcompatibility-wp' => 'phpcompatibility_wp',
	];
	$data = json_decode( (string) @file_get_contents( TOOL_DIR . '/vendor/composer/installed.json' ), true );
	foreach ( $data['packages'] ?? [] as $p ) {
		if ( isset( $map[ $p['name'] ] ) ) {
			$out[ $map[ $p['name'] ] ] = ltrim( $p['version'], 'v' );
		}
	}
	if ( '' !== $image ) {
		$out['image'] = $image;
	}
	return $out;
}

function odd_path( string $path ): bool {
	return trim( $path ) !== $path || false !== strpbrk( $path, "\r\n" );
}

/** @return int|float */
function cpu_count() {
	$max = @file_get_contents( '/sys/fs/cgroup/cpu.max' );
	if ( false !== $max && preg_match( '/^(\d+)\s+(\d+)/', $max, $m ) && (int) $m[2] > 0 ) {
		$n = (int) $m[1] / (int) $m[2];
		return $n == (int) $n ? (int) $n : round( $n, 2 );
	}
	$info = (string) @file_get_contents( '/proc/cpuinfo' );
	return max( 1, preg_match_all( '/^processor\s*:/m', $info ) );
}

function load_average(): ?float {
	$load = @file_get_contents( '/proc/loadavg' );
	return false === $load ? null : (float) strtok( $load, ' ' );
}

function env_int( string $name, int $default, int $min = 1 ): int {
	$v = getenv( $name );
	if ( false === $v || '' === $v ) {
		return $default;
	}
	if ( ! ctype_digit( $v ) || (int) $v < $min ) {
		throw new BadArgs( "$name must be an integer >= $min" );
	}
	return (int) $v;
}

function env_float( string $name, float $default ): float {
	$v = getenv( $name );
	if ( false === $v || '' === $v ) {
		return $default;
	}
	if ( ! is_numeric( $v ) || ! is_finite( (float) $v ) || (float) $v < 0 ) {
		throw new BadArgs( "$name must be a finite non-negative number" );
	}
	return (float) $v;
}

function env_memory( string $name, string $default ): string {
	$v = getenv( $name );
	if ( false === $v || '' === $v ) {
		return $default;
	}
	if ( ! preg_match( '/^\d+[KMG]?\z/', $v ) ) {
		throw new BadArgs( "$name must look like 448M" );
	}
	return $v;
}

/** A path under /var/www; site-command keeps a --public-dir like `a//b` as typed. */
function mount_path( string $path, string $what ): string {
	$path = rtrim( (string) preg_replace( '#/+#', '/', $path ), '/' );
	if ( ( MOUNT_ROOT !== $path && 0 !== strpos( $path, MOUNT_ROOT . '/' ) ) || preg_match( '#/\.\.?(/|\z)|[\x00-\x1F\x7F]#', $path ) ) {
		throw new BadArgs( "$what must be an absolute path under " . MOUNT_ROOT );
	}
	return $path;
}

/**
 * An install's version: exactly one `$wp_version = '…';` or `"…"` line holding a plain version of at most 64 characters
 * (EE prints it as given), else '' (unknown).
 */
function wp_version( string $dir ): string {
	$fh = open_regular( $dir . '/wp-includes/version.php' );
	if ( null === $fh ) {
		return '';
	}
	$lines = [];
	foreach ( lines( $fh ) as $line ) {
		// A line too long to read may hold it: then the version is unknown.
		if ( null === $line || preg_match( '/\$wp_version\s*=/', $line ) ) {
			$lines[] = (string) $line;
		}
	}
	fclose( $fh );
	if ( 1 !== count( $lines ) || ! preg_match( '/^\s*\$wp_version\s*=\s*([\'"])(\d+\.\d+[0-9A-Za-z.+-]*)\1\s*;\s*$/', $lines[0], $m ) ) {
		return '';
	}
	return strlen( $m[2] ) > 64 ? '' : $m[2];
}

/**
 * A file's lines without their `\n`, or null for one longer than LINE_MAX - 2 bytes, so no file size matters.
 *
 * @param resource $fh
 * @return Generator<int,string|null>
 */
function lines( $fh ): Generator {
	$long = false;
	while ( false !== ( $piece = fgets( $fh, LINE_MAX ) ) ) {
		if ( "\n" !== substr( $piece, -1 ) && ! feof( $fh ) ) {
			$long = true;
			continue;
		}
		yield $long ? null : rtrim( $piece, "\n" );
		$long = false;
	}
	// A last piece that filled the buffer exactly, with no line break after it.
	if ( $long ) {
		yield null;
	}
}

/** @return array<string,string> Functions PHP added since 8.1, by version, as the scanner's PHPCS sniff reads them too. */
function native_since(): array {
	static $since = null;
	$since = $since ?? require TOOL_DIR . '/src/native-functions.php';
	return $since;
}

/** major.minor of a WordPress version, as EE's support table names branches. */
function wp_branch( string $version ): string {
	return preg_match( '/^\d+\.\d+/', $version, $m ) ? $m[0] : '';
}

function parse_args( array $argv, array &$cfg ): void {
	$cfg['mode']      = $argv[0] ?? '';
	$cfg['site_type'] = $argv[1] ?? '';
	$cfg['path']      = $argv[2] ?? '';
	$cfg['version']   = (string) ( $argv[3] ?? '' );
	$timeout          = $argv[4] ?? '';

	if ( ! in_array( $cfg['mode'], [ 'scan', 'estimate' ], true ) ) {
		throw new BadArgs( 'mode must be scan or estimate' );
	}
	if ( ! in_array( $cfg['site_type'], [ 'wp', 'php' ], true ) ) {
		throw new BadArgs( 'site type must be wp or php' );
	}
	$cfg['path'] = mount_path( $cfg['path'], 'path' );
	parse_contract_env( $cfg );
	if ( ! preg_match( '/^\d+\.\d+\z/', $cfg['version'] ) ) {
		throw new BadArgs( 'version must look like 8.4' );
	}
	if ( 'scan' === $cfg['mode'] || '' !== $timeout ) {
		if ( ! ctype_digit( (string) $timeout ) || (int) $timeout < 1 ) {
			throw new BadArgs( 'timeout must be a positive integer' );
		}
	}
	$cfg['timeout'] = (int) $timeout;

	$cfg['batch_size']        = env_int( 'COMPAT_BATCH_SIZE', 200 );
	$cfg['batch_memory']      = env_memory( 'COMPAT_BATCH_MEMORY', '448M' );
	$cfg['file_memory']       = env_memory( 'COMPAT_FILE_MEMORY', $cfg['batch_memory'] );
	$cfg['retry_memory']      = env_memory( 'COMPAT_RETRY_MEMORY', '960M' );
	$cfg['estimate_timeout']  = env_int( 'COMPAT_ESTIMATE_TIMEOUT', 120 );
	$cfg['seconds_per_batch'] = env_float( 'COMPAT_SECONDS_PER_BATCH', 0.1 );
	$cfg['low_factor']        = env_float( 'COMPAT_LOW_FACTOR', 0.8 );
	$cfg['high_factor']       = env_float( 'COMPAT_HIGH_FACTOR', 1.5 );
	$cfg['report_max']        = env_int( 'COMPAT_REPORT_MAX', REPORT_MAX, 1024 );
	$cfg['sniffed_timeout']   = env_int( 'COMPAT_SNIFFED_TIMEOUT', 30 );
	$cfg['file_timeout']      = env_int( 'COMPAT_FILE_TIMEOUT', 120 );
	$cfg['manifest']          = 'scan' === $cfg['mode'] && '1' === getenv( 'COMPAT_MANIFEST' );
	if ( $cfg['low_factor'] > 1 || $cfg['high_factor'] < 1 ) {
		throw new BadArgs( 'COMPAT_LOW_FACTOR must be at most 1 and COMPAT_HIGH_FACTOR at least 1' );
	}
}

/** COMPAT_SERVED, COMPAT_REQUIRE, COMPAT_EXTRA_ROOTS and COMPAT_WP_SUPPORTED: what EE tells the scanner about the site. */
function parse_contract_env( array &$cfg ): void {
	// False when absent: a v3.11.1 call, unlike an empty value.
	$cfg['served'] = getenv( 'COMPAT_SERVED' );
	if ( is_string( $cfg['served'] ) && '' !== $cfg['served'] ) {
		$cfg['served'] = mount_path( $cfg['served'], 'COMPAT_SERVED' );
	}
	$cfg['require'] = array_values( array_filter( array_map( 'trim', explode( "\n", (string) getenv( 'COMPAT_REQUIRE' ) ) ), 'strlen' ) );
	$cfg['extra_roots'] = [];
	foreach ( array_filter( explode( "\n", (string) getenv( 'COMPAT_EXTRA_ROOTS' ) ), 'strlen' ) as $root ) {
		$malformed = '/' !== $root[0] || preg_match( '#//|/\.\.?(/|\z)|/\z|[\x00-\x1F\x7F]#', $root );
		if ( $malformed || MOUNT_ROOT === $root || 0 === strpos( $root, MOUNT_ROOT . '/' ) ) {
			throw new BadArgs( 'COMPAT_EXTRA_ROOTS must be absolute paths outside ' . MOUNT_ROOT . ', one per line' );
		}
		$cfg['extra_roots'][] = $root;
	}
	$supported           = (string) getenv( 'COMPAT_WP_SUPPORTED' );
	$cfg['wp_supported'] = '' === $supported ? [] : explode( ',', $supported );
	foreach ( $cfg['wp_supported'] as $branch ) {
		if ( ! preg_match( '/^\d+\.\d+\z/', $branch ) ) {
			throw new BadArgs( 'COMPAT_WP_SUPPORTED must be branches like 6.8, comma-separated' );
		}
	}
}

function emit( array $doc, int $code, bool $report ): void {
	global $emitted;
	$emitted = true;
	if ( $report && 'ok' !== $doc['status'] ) {
		@unlink( OUT_DIR . '/manifest.json' ); // Only an ok scan has one.
	}
	$json    = json_encode( $doc, JSON_FLAGS ) . "\n";
	if ( $report ) {
		$tmp = OUT_DIR . '/report.json.tmp';
		if ( ! ( is_dir( OUT_DIR ) && is_writable( OUT_DIR ) && strlen( $json ) === @file_put_contents( $tmp, $json ) && @rename( $tmp, OUT_DIR . '/report.json' ) ) ) {
			@unlink( $tmp );
			// The report is part of the result: without it only a tool_error stands.
			if ( 'tool_error' !== $doc['status'] ) {
				@unlink( OUT_DIR . '/manifest.json' );
				$doc['status'] = 'tool_error';
				$doc['detail'] = 'could not write the report';
				$json          = json_encode( $doc, JSON_FLAGS ) . "\n";
				$code          = 1;
			}
		}
	}
	fwrite( STDOUT, $json );
	exit( $code );
}

// ----------------------------------------------------------------------- main

// No core dumps of scanned code, for this process and every PHPCS run.
if ( function_exists( 'posix_setrlimit' ) ) {
	@posix_setrlimit( POSIX_RLIMIT_CORE, 0, 0 );
}

$emitted = false;
$scanner = null;
$cfg     = [
	'mode'    => '',
	'version' => '',
	'site'    => (string) getenv( 'COMPAT_SITE' ),
	'image'   => (string) getenv( 'COMPAT_IMAGE' ),
	'debug'   => '1' === getenv( 'COMPAT_DEBUG' ),
];

$tool_error = static function ( string $detail ) use ( &$cfg ): array {
	$doc = doc_head( $cfg, 'tool_error' );

	$doc['detail'] = $detail;
	return $doc;
};

// A fatal error (e.g. memory) still ends with one tool_error document on stdout.
$reserve = str_repeat( ' ', 262144 );
register_shutdown_function(
	static function () use ( &$reserve, &$scanner, &$cfg, $tool_error ) {
		global $emitted;
		$reserve = null;
		$e       = error_get_last();
		if ( $emitted || null === $e || ! in_array( $e['type'], [ E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_PARSE ], true ) ) {
			return;
		}
		if ( $scanner instanceof Scanner ) {
			$scanner->removeWork();
		}
		emit( $tool_error( 'internal error: ' . clean_text( $e['message'] ) ), 1, 'scan' === $cfg['mode'] );
	}
);

try {
	parse_args( array_slice( $argv, 1 ), $cfg );
} catch ( BadArgs $e ) {
	emit( $tool_error( 'bad arguments: ' . $e->getMessage() ), 2, false );
}

$isScan = 'scan' === $cfg['mode'];
if ( $isScan && ( ! is_dir( OUT_DIR ) || ! is_writable( OUT_DIR ) ) ) {
	emit( $tool_error( 'output directory not writable' ), 1, false );
}

$scanner = new Scanner( $cfg );
try {
	$doc = $scanner->run();
	emit( $doc, 0, $isScan && 'ok' !== $doc['status'] );
} catch ( TimedOut $e ) {
	$scanner->removeWork();
	emit( $tool_error( $e->getMessage() ), 1, $isScan );
} catch ( Throwable $e ) {
	$scanner->removeWork();
	$msg = $e instanceof ToolError ? $e->getMessage() : 'internal error: ' . clean_text( $e->getMessage() );
	emit( $tool_error( $msg ), 1, $isScan );
}
