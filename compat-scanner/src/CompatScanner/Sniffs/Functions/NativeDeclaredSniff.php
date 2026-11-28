<?php
/**
 * A global function declared outside any condition whose name PHP itself has in the target version: fatal there
 * ("Cannot redeclare function"), even after an early return, since PHP binds it when it compiles the file.
 */

namespace CompatScanner\Sniffs\Functions;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;
use PHPCSUtils\BackCompat\Helper;
use PHPCSUtils\Utils\Namespaces;

class NativeDeclaredSniff implements Sniff {

	/** @var array<string,string>|null */
	private $since;

	public function register() {
		return [ T_FUNCTION ];
	}

	public function process( File $phpcsFile, int $stackPtr ) {
		$this->since = $this->since ?? require __DIR__ . '/../../../native-functions.php';
		$name        = (string) $phpcsFile->getDeclarationName( $stackPtr );
		$since       = $this->since[ strtolower( $name ) ] ?? null;
		if ( null === $since || version_compare( (string) Helper::getConfigData( 'testVersion' ), $since, '<' ) ) {
			return;
		}
		// Inside a function_exists() check, a class or a function, or in a namespace, it is another function.
		if ( $phpcsFile->getTokens()[ $stackPtr ]['conditions'] || '' !== Namespaces::determineNamespace( $phpcsFile, $stackPtr ) ) {
			return;
		}
		$message = 'Function %s() is native since PHP %s; declaring it without a function_exists() check is fatal there';
		$phpcsFile->addError( $message, $stackPtr, 'Found', [ $name, $since ] );
	}
}
