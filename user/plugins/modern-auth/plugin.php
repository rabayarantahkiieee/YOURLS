<?php
/*
Plugin Name: Modern Auth & Landing Page
Plugin URI: https://yourls.org/
Description: Adds self-service registration and password reset (multi-user login on top of the config.php admin), a t.ly-style public landing page at the site root, and a restyled login/register screen. Activate this plugin from the Plugins page after install.
Version: 1.1
Author: -
Author URI: -
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

define( 'MODERN_AUTH_TABLE', YOURLS_DB_PREFIX . 'users' );

/**
 * Make sure the users table exists. Runs once (flag stored in options) then is a no-op.
 */
yourls_add_action( 'plugins_loaded', 'modern_auth_maybe_create_table' );
function modern_auth_maybe_create_table() {
    if ( yourls_get_option( 'modern_auth_db_ready' ) ) {
        return;
    }

    $table = MODERN_AUTH_TABLE;
    $pdo = yourls_get_db('write-modern_auth_create_table')->getPdo();
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS `$table` (
            `id` INT(11) UNSIGNED NOT NULL AUTO_INCREMENT,
            `username` VARCHAR(50) NOT NULL,
            `email` VARCHAR(191) NOT NULL,
            `password_hash` VARCHAR(255) NOT NULL,
            `created_at` DATETIME NOT NULL,
            `reset_token_hash` VARCHAR(64) NULL,
            `reset_token_expires` DATETIME NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `username` (`username`),
            UNIQUE KEY `email` (`email`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
    );

    // Migration for tables created before password reset existed. Plain "IF NOT EXISTS" on
    // ADD COLUMN is a MariaDB-only extension and errors out (1064) on real MySQL, so check
    // information_schema first instead.
    modern_auth_add_column_if_missing( $pdo, $table, 'reset_token_hash', 'VARCHAR(64) NULL' );
    modern_auth_add_column_if_missing( $pdo, $table, 'reset_token_expires', 'DATETIME NULL' );

    yourls_update_option( 'modern_auth_db_ready', true );
}

function modern_auth_add_column_if_missing( PDO $pdo, string $table, string $column, string $definition ) {
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table AND COLUMN_NAME = :column'
    );
    $stmt->execute( [ 'table' => $table, 'column' => $column ] );
    if ( (int) $stmt->fetchColumn() > 0 ) {
        return;
    }
    $pdo->exec( "ALTER TABLE `$table` ADD COLUMN `$column` $definition" );
}

/**
 * Look up a registered (DB) user by username
 *
 * @param string $username
 * @return array|null
 */
function modern_auth_get_user( $username ) {
    $ydb = yourls_get_db('read-modern_auth_get_user');
    $table = MODERN_AUTH_TABLE;
    $row = $ydb->fetchOne( "SELECT * FROM `$table` WHERE `username` = :username LIMIT 1", [ 'username' => $username ] );
    return $row ?: null;
}

/**
 * Second-chance auth check: if core auth (config.php admins) failed, check the DB-backed
 * users table (self-registered users) instead -- both for a username/password login
 * submission, and for the auth cookie on later page loads (core's yourls_check_auth_cookie()
 * only ever compares against the config.php $yourls_user_passwords array, so without this,
 * a DB user could log in once but would be treated as logged-out on the very next request).
 *
 * Hooked on the 'is_valid_user' filter, which core calls after its own check, with final say.
 * Nonce and login-flood throttling already happened in yourls_check_username_password()
 * regardless of outcome, so both auth paths share the same brute-force protection.
 */
yourls_add_filter( 'is_valid_user', 'modern_auth_check_db_user' );
function modern_auth_check_db_user( $valid ) {
    if ( $valid === true ) {
        return true;
    }

    // Username/password login submission
    if ( !empty( $_REQUEST['username'] ) && !empty( $_REQUEST['password'] ) ) {
        $user = modern_auth_get_user( (string) $_REQUEST['username'] );
        if ( $user && password_verify( (string) $_REQUEST['password'], $user['password_hash'] ) ) {
            yourls_set_user( $user['username'] );
            yourls_clear_login_flood();
            return true;
        }
        return $valid;
    }

    // Returning visit: check the auth cookie against each DB user's expected cookie value
    if ( !yourls_is_API() && isset( $_COOKIE[ yourls_cookie_name() ] ) ) {
        foreach ( modern_auth_get_usernames() as $username ) {
            if ( hash_equals( yourls_cookie_value( $username ), (string) $_COOKIE[ yourls_cookie_name() ] ) ) {
                yourls_set_user( $username );
                return true;
            }
        }
    }

    return $valid;
}

/**
 * @return string[] all registered (DB) usernames
 */
function modern_auth_get_usernames(): array {
    $ydb = yourls_get_db('read-modern_auth_get_usernames');
    $table = MODERN_AUTH_TABLE;
    return $ydb->fetchCol( "SELECT `username` FROM `$table`" );
}

/**
 * Handle registration form submission (POST to this page with modern_auth_register=1)
 * Hooked very early so it can redirect before any HTML is sent.
 */
yourls_add_action( 'plugins_loaded', 'modern_auth_handle_registration' );
function modern_auth_handle_registration() {
    if ( yourls_is_API() || empty( $_POST['modern_auth_register'] ) ) {
        return;
    }

    yourls_verify_nonce( 'modern_auth_register' );
    modern_auth_check_register_flood();

    $username = isset( $_POST['username'] ) ? trim( (string) $_POST['username'] ) : '';
    $email    = isset( $_POST['email'] )    ? trim( (string) $_POST['email'] )    : '';
    $password = isset( $_POST['password'] ) ? (string) $_POST['password']         : '';

    $error = modern_auth_validate_registration( $username, $email, $password );

    if ( !$error ) {
        $ydb = yourls_get_db('write-modern_auth_register');
        $table = MODERN_AUTH_TABLE;
        $inserted = $ydb->fetchAffected(
            "INSERT INTO `$table` (`username`, `email`, `password_hash`, `created_at`) VALUES (:username, :email, :hash, :created_at)",
            [
                'username'   => $username,
                'email'      => $email,
                'hash'       => password_hash( $password, PASSWORD_DEFAULT ),
                'created_at' => date( 'Y-m-d H:i:s' ),
            ]
        );

        if ( $inserted ) {
            modern_auth_register_flood_hit( true );
            yourls_redirect( yourls_add_query_arg( 'registered', '1', yourls_site_url( false ) . '/admin/' ), 302 );
            exit;
        }

        $error = yourls__( 'Could not create account (username or email may already be taken).' );
    }

    modern_auth_register_flood_hit( false );
    $GLOBALS['modern_auth_register_error'] = $error;
    $GLOBALS['modern_auth_register_values'] = [ 'username' => $username, 'email' => $email ];
}

function modern_auth_validate_registration( $username, $email, $password ) {
    if ( !preg_match( '/^[a-zA-Z0-9_-]{3,50}$/', $username ) ) {
        return yourls__( 'Username must be 3-50 characters: letters, digits, - or _ only.' );
    }
    if ( !filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
        return yourls__( 'Please provide a valid email address.' );
    }
    if ( strlen( $password ) < 10 ) {
        return yourls__( 'Password must be at least 10 characters long.' );
    }
    if ( modern_auth_get_user( $username ) ) {
        return yourls__( 'This username is already taken.' );
    }
    // Reject usernames that collide with a config.php admin: config auth wins at login, so such
    // an account could never actually log in, and it would share an owner identity (and thus link
    // ownership) with that admin. Keep owner identities unambiguous.
    $config_admins = array_keys( (array) ( $GLOBALS['yourls_user_passwords'] ?? [] ) );
    if ( in_array( $username, $config_admins, true ) ) {
        return yourls__( 'This username is not available.' );
    }
    return '';
}

/**
 * Lightweight per-IP rate limit for registration attempts (mitigates spam signups),
 * stored the same way as the core login flood throttle: a self-pruning options-table entry.
 */
function modern_auth_check_register_flood() {
    $data = modern_auth_register_flood_data();
    $max_attempts = (int) yourls_apply_filter( 'register_flood_max_attempts', 5 );
    if ( $data['count'] >= $max_attempts ) {
        yourls_die( yourls__( 'Too many registration attempts. Please try again later.' ), yourls__( 'Too Many Requests' ), 429 );
    }
}

function modern_auth_register_flood_hit( $success ) {
    if ( $success ) {
        yourls_delete_option( modern_auth_register_flood_key() );
        return;
    }
    $data = modern_auth_register_flood_data();
    $data['count']++;
    $key = modern_auth_register_flood_key();
    if ( false === yourls_get_option( $key, false ) ) {
        yourls_add_option( $key, $data );
    } else {
        yourls_update_option( $key, $data );
    }
}

function modern_auth_register_flood_data(): array {
    $window = (int) yourls_apply_filter( 'register_flood_window', 3600 ); // 1 hour
    $data = yourls_get_option( modern_auth_register_flood_key(), [ 'count' => 0, 'first' => time() ] );
    if ( ( time() - $data['first'] ) > $window ) {
        $data = [ 'count' => 0, 'first' => time() ];
    }
    return $data;
}

function modern_auth_register_flood_key(): string {
    // option_name is varchar(64): keep the key well under that limit
    return 'rf_' . substr( hash( 'sha256', yourls_get_IP() ), 0, 40 );
}

/**
 * @param string $email
 * @return array|null
 */
function modern_auth_get_user_by_email( string $email ) {
    $ydb = yourls_get_db('read-modern_auth_get_user_by_email');
    $table = MODERN_AUTH_TABLE;
    $row = $ydb->fetchOne( "SELECT * FROM `$table` WHERE `email` = :email LIMIT 1", [ 'email' => $email ] );
    return $row ?: null;
}

/**
 * @param string $token raw (unhashed) token as received from the reset link
 * @return array|null the matching user row, if the token is valid and not expired
 */
function modern_auth_get_user_by_reset_token( string $token ) {
    if ( $token === '' ) {
        return null;
    }
    $ydb = yourls_get_db('read-modern_auth_get_user_by_reset_token');
    $table = MODERN_AUTH_TABLE;
    $row = $ydb->fetchOne(
        "SELECT * FROM `$table` WHERE `reset_token_hash` = :hash AND `reset_token_expires` > :now LIMIT 1",
        [ 'hash' => hash( 'sha256', $token ), 'now' => date( 'Y-m-d H:i:s' ) ]
    );
    return $row ?: null;
}

/**
 * Handle "forgot password" form submission: generate a one-hour token and email a reset link.
 * Always redirects to the same "check your email" message whether or not the address is
 * registered, so this can't be used to enumerate accounts.
 */
yourls_add_action( 'plugins_loaded', 'modern_auth_handle_forgot_password' );
function modern_auth_handle_forgot_password() {
    if ( yourls_is_API() || empty( $_POST['modern_auth_forgot_password'] ) ) {
        return;
    }

    yourls_verify_nonce( 'modern_auth_forgot_password' );
    modern_auth_check_forgot_flood();

    $email = isset( $_POST['email'] ) ? trim( (string) $_POST['email'] ) : '';

    if ( filter_var( $email, FILTER_VALIDATE_EMAIL ) ) {
        $user = modern_auth_get_user_by_email( $email );
        if ( $user ) {
            $token   = bin2hex( random_bytes( 32 ) );
            $expires = date( 'Y-m-d H:i:s', time() + 3600 );

            $ydb = yourls_get_db('write-modern_auth_set_reset_token');
            $table = MODERN_AUTH_TABLE;
            $ydb->fetchAffected(
                "UPDATE `$table` SET `reset_token_hash` = :hash, `reset_token_expires` = :expires WHERE `id` = :id",
                [ 'hash' => hash( 'sha256', $token ), 'expires' => $expires, 'id' => $user['id'] ]
            );

            $reset_url = yourls_add_query_arg( 'token', $token, yourls_site_url( false ) . '/reset-password.php' );
            modern_auth_send_mail(
                $email,
                'Reset your password',
                "Someone requested a password reset for your account.\n\nReset it here (valid 1 hour):\n$reset_url\n\nIf you didn't request this, you can ignore this email."
            );
        }
        modern_auth_forgot_flood_hit(); // count real attempts (valid email format) toward the throttle
    }

    yourls_redirect( yourls_add_query_arg( 'sent', '1', yourls_site_url( false ) . '/forgot-password.php' ), 302 );
    exit;
}

/**
 * Handle the "set a new password" form submission from reset-password.php
 */
yourls_add_action( 'plugins_loaded', 'modern_auth_handle_reset_password' );
function modern_auth_handle_reset_password() {
    if ( yourls_is_API() || empty( $_POST['modern_auth_reset_password'] ) ) {
        return;
    }

    yourls_verify_nonce( 'modern_auth_reset_password' );

    $token    = isset( $_POST['token'] )    ? (string) $_POST['token']    : '';
    $password = isset( $_POST['password'] ) ? (string) $_POST['password'] : '';

    $user = modern_auth_get_user_by_reset_token( $token );
    if ( !$user ) {
        $GLOBALS['modern_auth_reset_error'] = yourls__( 'This reset link is invalid or has expired.' );
        return;
    }
    if ( strlen( $password ) < 10 ) {
        $GLOBALS['modern_auth_reset_error'] = yourls__( 'Password must be at least 10 characters long.' );
        $GLOBALS['modern_auth_reset_token'] = $token;
        return;
    }

    $ydb = yourls_get_db('write-modern_auth_reset_password');
    $table = MODERN_AUTH_TABLE;
    $ydb->fetchAffected(
        "UPDATE `$table` SET `password_hash` = :hash, `reset_token_hash` = NULL, `reset_token_expires` = NULL WHERE `id` = :id",
        [ 'hash' => password_hash( $password, PASSWORD_DEFAULT ), 'id' => $user['id'] ]
    );

    yourls_redirect( yourls_add_query_arg( 'reset', '1', yourls_site_url( false ) . '/admin/' ), 302 );
    exit;
}

/**
 * Send an email: uses a minimal built-in SMTP client (STARTTLS + AUTH LOGIN) when SMTP_HOST
 * is configured, otherwise falls back to PHP's mail(), which needs a working local MTA and
 * often does NOT work out of the box in a container -- set SMTP_* env vars for reliable delivery.
 */
function modern_auth_send_mail( string $to, string $subject, string $body ): bool {
    $host = getenv('SMTP_HOST');
    if ( $host ) {
        return modern_auth_send_mail_smtp( $host, $to, $subject, $body );
    }

    $from = getenv('MAIL_FROM') ?: ( 'no-reply@' . parse_url( yourls_get_yourls_site(), PHP_URL_HOST ) );
    $headers = "From: $from\r\nContent-Type: text/plain; charset=UTF-8\r\n";
    $sent = @mail( $to, $subject, $body, $headers );
    if ( !$sent ) {
        yourls_debug_log( "modern-auth: mail() failed sending to $to -- configure SMTP_HOST for reliable delivery" );
    }
    return $sent;
}

function modern_auth_send_mail_smtp( string $host, string $to, string $subject, string $body ): bool {
    $port = (int) ( getenv('SMTP_PORT') ?: 587 );
    $user = getenv('SMTP_USER');
    $pass = getenv('SMTP_PASS');
    $from = getenv('MAIL_FROM') ?: ( $user ?: ( 'no-reply@' . parse_url( yourls_get_yourls_site(), PHP_URL_HOST ) ) );
    $helo = parse_url( yourls_get_yourls_site(), PHP_URL_HOST ) ?: 'localhost';

    $errno = 0;
    $errstr = '';
    $sock = @stream_socket_client( "tcp://$host:$port", $errno, $errstr, 10 );
    if ( !$sock ) {
        yourls_debug_log( "modern-auth: SMTP connect to $host:$port failed: $errstr" );
        return false;
    }

    $read = static function () use ( $sock ) {
        $data = '';
        while ( ( $line = fgets( $sock, 515 ) ) !== false ) {
            $data .= $line;
            if ( isset( $line[3] ) && $line[3] === ' ' ) {
                break;
            }
        }
        return $data;
    };
    $write = static function ( $cmd ) use ( $sock ) {
        fwrite( $sock, $cmd . "\r\n" );
    };
    $ok = static function ( $resp, $code ) {
        return str_starts_with( $resp, (string) $code );
    };

    $read(); // server greeting
    $write( "EHLO $helo" );
    $ehlo = $read();

    if ( str_contains( $ehlo, 'STARTTLS' ) ) {
        $write( 'STARTTLS' );
        $read();
        if ( !stream_socket_enable_crypto( $sock, true, STREAM_CRYPTO_METHOD_TLS_CLIENT ) ) {
            fclose( $sock );
            yourls_debug_log( 'modern-auth: SMTP STARTTLS negotiation failed' );
            return false;
        }
        $write( "EHLO $helo" );
        $read();
    }

    if ( $user && $pass ) {
        $write( 'AUTH LOGIN' );
        $read();
        $write( base64_encode( $user ) );
        $read();
        $write( base64_encode( $pass ) );
        if ( !$ok( $read(), 235 ) ) {
            fclose( $sock );
            yourls_debug_log( 'modern-auth: SMTP authentication failed' );
            return false;
        }
    }

    $write( "MAIL FROM:<$from>" );
    $read();
    $write( "RCPT TO:<$to>" );
    $read();
    $write( 'DATA' );
    $read();

    $message = "From: $from\r\nTo: $to\r\nSubject: $subject\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n$body\r\n.";
    $write( $message );
    $result = $ok( $read(), 250 );

    $write( 'QUIT' );
    fclose( $sock );

    if ( !$result ) {
        yourls_debug_log( "modern-auth: SMTP send to $to was rejected" );
    }
    return $result;
}

/**
 * Rate limit for "forgot password" requests -- separate bucket from registration/login,
 * same self-pruning options-table pattern.
 */
function modern_auth_check_forgot_flood() {
    $data = modern_auth_forgot_flood_data();
    $max_attempts = (int) yourls_apply_filter( 'forgot_password_flood_max_attempts', 5 );
    if ( $data['count'] >= $max_attempts ) {
        yourls_die( yourls__( 'Too many requests. Please try again later.' ), yourls__( 'Too Many Requests' ), 429 );
    }
}

function modern_auth_forgot_flood_hit() {
    $data = modern_auth_forgot_flood_data();
    $data['count']++;
    $key = modern_auth_forgot_flood_key();
    if ( false === yourls_get_option( $key, false ) ) {
        yourls_add_option( $key, $data );
    } else {
        yourls_update_option( $key, $data );
    }
}

function modern_auth_forgot_flood_data(): array {
    $window = (int) yourls_apply_filter( 'forgot_password_flood_window', 3600 ); // 1 hour
    $data = yourls_get_option( modern_auth_forgot_flood_key(), [ 'count' => 0, 'first' => time() ] );
    if ( ( time() - $data['first'] ) > $window ) {
        $data = [ 'count' => 0, 'first' => time() ];
    }
    return $data;
}

function modern_auth_forgot_flood_key(): string {
    return 'ff_' . substr( hash( 'sha256', yourls_get_IP() ), 0, 40 );
}

/**
 * Modern styling: inject the plugin's stylesheet on every admin page, plus the QR code
 * library and its render script on the pages that show the links table (index/bookmark).
 *
 * Note: yourls_do_action('html_head', $context) delivers $context wrapped in a
 * single-element array to action callbacks (accepted_args=1 default in yourls_add_action()
 * combined with how yourls_do_action()/yourls_apply_filter() pass args through) -- unwrap it.
 */
yourls_add_filter( 'bodyclass', 'modern_auth_add_bodyclass' );
function modern_auth_add_bodyclass( $bodyclass ) {
    // Note: core does $bodyclass .= 'mobile'/'desktop' right after this filter runs, with
    // no separator -- keep a trailing space so the two class names don't get glued together.
    return $bodyclass . 'modern-space-bg ';
}

yourls_add_action( 'html_head', 'modern_auth_admin_assets' );
function modern_auth_admin_assets( $context ) {
    $context = is_array( $context ) ? ( $context[0] ?? null ) : $context;
    $base = yourls_plugin_url( __DIR__ );

    echo '<link rel="stylesheet" href="' . yourls_esc_attr( $base . '/assets/modern.css' ) . '" type="text/css" media="screen" />' . "\n";

    if ( in_array( $context, [ 'index', 'bookmark' ], true ) ) {
        echo '<script src="' . yourls_esc_attr( $base . '/assets/vendor/qrcode.js' ) . '"></script>' . "\n";
        echo '<script src="' . yourls_esc_attr( $base . '/assets/vendor/qrcode_UTF8.js' ) . '"></script>' . "\n";
        echo '<script src="' . yourls_esc_attr( $base . '/assets/qr-render.js' ) . '"></script>' . "\n";
        echo '<script src="' . yourls_esc_attr( $base . '/assets/bulk.js' ) . '"></script>' . "\n";
        echo '<script src="' . yourls_esc_attr( $base . '/assets/tags.js' ) . '"></script>' . "\n";
    }

    if ( $context === 'infos' ) {
        echo '<script src="' . yourls_esc_attr( $base . '/assets/analytics.js' ) . '"></script>' . "\n";
    }
}

/**
 * Replace the default "YOURLS: Your Own URL Shortener" header (wordmark image + text) with
 * just a recolored version of the same logo artwork, no text.
 *
 * Reuses core's own logo image (images/yourls-logo.svg) rather than shipping a new one, tinted
 * violet/glowing via a CSS filter (hue-rotate + saturate + drop-shadow) to fit the space theme.
 * A flat-color mask was tried first but flattened the letterforms into an unreadable blob;
 * hue-rotate keeps the original's light/dark contrast, so "YOURLS" stays legible.
 * The original <header> (image + "YOURLS: Your Own URL Shortener" text) is hidden by CSS;
 * this hooks the 'html_logo' action, which core fires right after that original header.
 */
yourls_add_action( 'html_logo', 'modern_auth_replace_logo' );
function modern_auth_replace_logo() {
    $logo_url = yourls_esc_attr( yourls_site_url( false ) . '/images/yourls-logo.svg' );
    echo '<a href="' . yourls_esc_attr( yourls_admin_url( 'index.php' ) ) . '" class="modern-brand-logo" title="YOURLS">'
       . '<img src="' . $logo_url . '" alt="YOURLS" class="modern-brand-logo-mark" />'
       . '</a>';
}

/**
 * Add a "Create an account" link under the login form.
 */
yourls_add_action( 'login_form_bottom', 'modern_auth_add_register_link' );
function modern_auth_add_register_link() {
    if ( isset( $_GET['registered'] ) ) {
        echo '<p class="modern-auth-success">' . yourls_esc_html__( 'Account created! You can now log in.' ) . '</p>';
    }
    if ( isset( $_GET['reset'] ) ) {
        echo '<p class="modern-auth-success">' . yourls_esc_html__( 'Password updated! You can now log in.' ) . '</p>';
    }
    $register_url = yourls_site_url( false ) . '/register.php';
    $forgot_url   = yourls_site_url( false ) . '/forgot-password.php';
    echo '<p class="modern-auth-register-link"><a href="' . yourls_esc_attr( $forgot_url ) . '">' . yourls_esc_html__( 'Forgot your password?' ) . '</a></p>';
    echo '<p class="modern-auth-register-link"><a href="' . yourls_esc_attr( $register_url ) . '">' . yourls_esc_html__( 'Create an account' ) . '</a></p>';
}

/**
 * Public landing page at the bare site root (t.ly-style), instead of the default
 * "keyword not found, redirect to site root" behaviour, which for an EMPTY keyword
 * would otherwise just bounce back to itself.
 *
 * Note: see comment on modern_auth_admin_assets() above -- $keyword arrives array-wrapped.
 */
yourls_add_action( 'redirect_keyword_not_found', 'modern_auth_landing_page' );
function modern_auth_landing_page( $keyword ) {
    $keyword = is_array( $keyword ) ? ( $keyword[0] ?? null ) : $keyword;
    if ( $keyword !== '' && $keyword !== null ) {
        return; // real 404: let core handle it (redirect to site root)
    }

    require __DIR__ . '/landing.php';
    exit;
}

/**
 * Handle the "shorten a link" form on the public landing page. Only actually creates the
 * link if the visitor already has a valid session (admin from config.php, or a logged-in
 * DB user) -- yourls_is_valid_user() checks the existing auth cookie here since there's no
 * username/password in this form, it does NOT attempt or require a fresh login. Anonymous
 * visitors just get a prompt to log in first, with their input kept so the form isn't wiped.
 *
 * Hooked on 'plugins_loaded' (fires during bootstrap, before the router decides to show
 * landing.php) so the $GLOBALS below are already set by the time landing.php reads them.
 */
yourls_add_action( 'plugins_loaded', 'modern_auth_handle_landing_shorten' );
function modern_auth_handle_landing_shorten() {
    if ( yourls_is_API() || empty( $_POST['modern_auth_landing_shorten'] ) ) {
        return;
    }

    yourls_verify_nonce( 'landing_shorten' );

    $url     = isset( $_POST['url'] )     ? trim( (string) $_POST['url'] )     : '';
    $keyword = isset( $_POST['keyword'] ) ? trim( (string) $_POST['keyword'] ) : '';

    $GLOBALS['modern_auth_landing_shorten_values'] = [ 'url' => $url, 'keyword' => $keyword ];

    if ( yourls_is_valid_user() !== true ) {
        $GLOBALS['modern_auth_landing_shorten_error'] = yourls__( 'Please log in or create a free account first to shorten a link.' );
        return;
    }

    $return = yourls_add_new_link( $url, $keyword );

    if ( isset( $return['status'] ) && $return['status'] === 'success' && !empty( $return['shorturl'] ) ) {
        $GLOBALS['modern_auth_landing_shorten_result'] = $return['shorturl'];
        $GLOBALS['modern_auth_landing_shorten_values'] = [ 'url' => '', 'keyword' => '' ];
    } else {
        $GLOBALS['modern_auth_landing_shorten_error'] = $return['message'] ?? yourls__( 'Could not shorten that link.' );
    }
}

/**
 * ---------------------------------------------------------------------------
 * Modern dashboard: 2-column layout (links table + sidebar), QR code and
 * "unique visitors" columns in the table, matching the t.ly-inspired redesign.
 * ---------------------------------------------------------------------------
 */

/**
 * Open the 2-column dashboard wrapper right after the page header/menu.
 */
yourls_add_action( 'admin_page_before_content', 'modern_auth_dashboard_open' );
function modern_auth_dashboard_open() {
    if ( !yourls_is_admin() ) {
        return;
    }
    echo '<div class="modern-dash"><div class="modern-dash-main">';
}

/**
 * Buffer the table markup so its "no results" placeholder row -- core hardcodes
 * <td colspan="6"> -- can be corrected to match the real column count now that this
 * plugin adds 2 extra columns (qr, unique). Without this, the tablesorter jQuery
 * plugin complains (and, worse, mis-renders) about a THEAD/row column mismatch.
 */
yourls_add_action( 'admin_page_before_table', 'modern_auth_table_buffer_start' );
function modern_auth_table_buffer_start() {
    if ( yourls_is_admin() ) {
        ob_start();
    }
}

yourls_add_action( 'admin_page_after_table', 'modern_auth_table_buffer_end', 5 );
function modern_auth_table_buffer_end() {
    if ( !yourls_is_admin() ) {
        return;
    }
    $html = ob_get_clean();
    $count = substr_count( $html, "<th id='main_table_head_" );
    if ( $count > 0 ) {
        // Two places hardcode colspan="6" for the original 6-column table: the "no results"
        // row (<td>) and the pagination row in the <tfoot> (<th>).
        $html = str_replace(
            [ '<td colspan="6">', '<th colspan="6">' ],
            [ '<td colspan="' . $count . '">', '<th colspan="' . $count . '">' ],
            $html
        );
    }
    echo $html;
}

/**
 * Close the main column and render the sidebar after the links table.
 */
yourls_add_action( 'admin_page_after_table', 'modern_auth_dashboard_sidebar' );
function modern_auth_dashboard_sidebar() {
    if ( !yourls_is_admin() ) {
        return;
    }

    $stats = yourls_get_db_stats();

    echo '</div><aside class="modern-dash-sidebar">';

    echo '<div class="modern-card"><h3>' . yourls_esc_html__( 'Overview' ) . '</h3>';
    echo '<div class="modern-stat-row"><span class="modern-stat-label">' . yourls_esc_html__( 'Total links' ) . '</span><span class="modern-stat-value">' . yourls_number_format_i18n( $stats['total_links'] ) . '</span></div>';
    echo '<div class="modern-stat-row"><span class="modern-stat-label">' . yourls_esc_html__( 'Total clicks' ) . '</span><span class="modern-stat-value">' . yourls_number_format_i18n( $stats['total_clicks'] ) . '</span></div>';
    echo '</div>';

    echo '<div class="modern-card"><h3>' . yourls_esc_html__( 'Tips' ) . '</h3>';
    echo '<div class="modern-tip"><span>&#128279;</span><span><strong>' . yourls_esc_html__( 'Custom keywords' ) . '</strong>' . yourls_esc_html__( 'Type your own keyword when shortening a link to get a memorable slug.' ) . '</span></div>';
    echo '<div class="modern-tip"><span>&#128202;</span><span><strong>' . yourls_esc_html__( 'Stats page' ) . '</strong>' . yourls_esc_html__( 'Add a + at the end of any short link to see clicks, referrers and countries.' ) . '</span></div>';
    echo '<div class="modern-tip"><span>&#9635;</span><span><strong>' . yourls_esc_html__( 'QR codes' ) . '</strong>' . yourls_esc_html__( 'Click the QR thumbnail next to a link to view or download it.' ) . '</span></div>';
    echo '</div>';

    echo '</aside></div>';
}

/**
 * Add "QR" and "Unique" column headers, appended at the very end (after "Actions").
 *
 * They can't be inserted in the middle of the existing columns: js/tablesorte.js hardcodes
 * column indexes (keyword=0, url=1, timestamp=2, ip=3, clicks=4, actions=5, with sorting
 * explicitly disabled on index 5). Appending after "actions" keeps those indexes intact so
 * sorting keeps working correctly; the 2 new columns just sort as plain text, which is fine.
 */
yourls_add_filter( 'table_head_cells', 'modern_auth_add_table_headers' );
function modern_auth_add_table_headers( $cells ) {
    $cells['qr']     = yourls__( 'QR Code' );
    $cells['unique'] = yourls__( 'Unique' );
    $cells['status'] = yourls__( 'Status' );
    $cells['tags']   = yourls__( 'Tags' );
    $cells['select'] = '<input type="checkbox" id="modern-select-all" title="' . yourls_esc_attr__( 'Select all' ) . '" />';
    return $cells;
}

/**
 * Add the matching "QR", "Unique", "Status", "Tags" and bulk-select cells to every table row, in
 * the same trailing order as the headers above.
 */
yourls_add_filter( 'table_add_row_cell_array', 'modern_auth_add_table_cells' );
function modern_auth_add_table_cells( $cells, $keyword, $url, $title, $ip, $clicks, $timestamp ) {
    $cells['qr'] = [
        'template' => '<div class="modern-qr-code" data-url="%url%"></div>',
        'url'      => yourls_esc_attr( yourls_link( $keyword ) ),
    ];
    $cells['unique'] = [
        'template' => '<span class="modern-badge">%unique%</span>',
        'unique'   => yourls_number_format_i18n( modern_auth_unique_visitors( $keyword ), 0 ),
    ];
    // Read-only: only the admin can suspend/reactivate a link (see the "All Links" moderation
    // page). A user sees their own link is suspended so a dead redirect isn't a mystery, but
    // has no control over it here.
    $cells['status'] = modern_auth_is_suspended( $keyword )
        ? [ 'template' => '<span class="modern-badge modern-badge-danger">%s%</span>', 's' => yourls_esc_html__( 'Suspended' ) ]
        : [ 'template' => '', 's' => '' ];
    $cells['tags'] = [ 'template' => '%tags%', 'tags' => modern_auth_render_tags_cell( $keyword ) ];
    $cells['select'] = [
        'template' => '<input type="checkbox" class="modern-bulk-select" name="modern_bulk[]" value="%keyword%" />',
        'keyword'  => yourls_esc_attr( $keyword ),
    ];
    return $cells;
}

/**
 * Small toolbar above the table: select-all + "Delete selected", wired up by assets/bulk.js
 * against the checkboxes added in modern_auth_add_table_cells() above. Hooked at priority 1 so
 * it runs (and echoes) before modern_auth_table_buffer_start()'s ob_start() on the same action,
 * i.e. it's rendered directly, above the buffered <table>, not swallowed into it.
 */
yourls_add_action( 'admin_page_before_table', 'modern_auth_bulk_toolbar', 1 );
function modern_auth_bulk_toolbar() {
    if ( !yourls_is_admin() ) {
        return;
    }
    $nonce = yourls_create_nonce( 'modern_auth_bulk_delete' );
    echo '<div class="modern-bulk-toolbar" id="modern-bulk-toolbar">';
    echo '<span id="modern-bulk-count">' . yourls_esc_html__( '0 selected' ) . '</span>';
    echo '<button type="button" id="modern-bulk-delete" class="button" disabled>' . yourls_esc_html__( 'Delete selected' ) . '</button>';
    echo '</div>';
    echo '<script>window.modernAuthBulkNonce = ' . json_encode( $nonce ) . ';</script>';
}

/**
 * AJAX endpoint for the bulk-delete button: admin-ajax.php's default case forwards any unknown
 * action to do_action('yourls_ajax_'.$action), which is the officially supported extension
 * point for exactly this. Deletion still goes through yourls_delete_link_by_keyword(), so the
 * existing ownership guard (modern_auth_guard_delete) applies per keyword -- a user can only
 * ever bulk-delete their own links, even if the request is tampered with to include someone
 * else's keyword (that keyword just silently fails and is reported back in "failed").
 */
yourls_add_action( 'yourls_ajax_modern_auth_bulk_delete', 'modern_auth_ajax_bulk_delete' );
function modern_auth_ajax_bulk_delete() {
    yourls_verify_nonce( 'modern_auth_bulk_delete', $_REQUEST['nonce'] ?? '', false, 'omg error' );

    $keywords = ( isset( $_REQUEST['keywords'] ) && is_array( $_REQUEST['keywords'] ) ) ? $_REQUEST['keywords'] : [];
    $failed = [];
    foreach ( $keywords as $keyword ) {
        $keyword = yourls_sanitize_keyword( (string) $keyword );
        if ( $keyword === '' || !yourls_delete_link_by_keyword( $keyword ) ) {
            $failed[] = $keyword;
        }
    }
    echo json_encode( [ 'success' => true, 'failed' => $failed ] );
}

/**
 * Count distinct IPs that clicked a given short URL.
 *
 * @param string $keyword
 * @return int
 */
function modern_auth_unique_visitors( string $keyword ): int {
    $table = YOURLS_DB_TABLE_LOG;
    $ydb = yourls_get_db('read-modern_auth_unique_visitors');
    return (int) $ydb->fetchValue(
        "SELECT COUNT(DISTINCT `ip_address`) FROM `$table` WHERE `shorturl` = :keyword",
        [ 'keyword' => $keyword ]
    );
}

/**
 * ---------------------------------------------------------------------------
 * "Manage Users" admin page: view/delete self-registered (DB) users. Shows up
 * as a sublink under "Manage Plugins" in the admin menu (core's own mechanism
 * for plugin admin pages -- see yourls_list_plugin_admin_pages()).
 * ---------------------------------------------------------------------------
 */
yourls_add_action( 'plugins_loaded', 'modern_auth_register_users_page' );
function modern_auth_register_users_page() {
    yourls_register_plugin_page( 'modern_auth_users', yourls__( 'Manage Users' ), 'modern_auth_users_page' );
}

function modern_auth_users_page() {
    // Defense in depth: this page is reached via plugins.php, which the auth_successful guard
    // already restricts to config admins -- but never render user management for anyone else.
    if ( !modern_auth_is_config_admin() ) {
        yourls_die( yourls__( 'You do not have permission to access this page.' ), yourls__( 'Access denied' ), 403 );
    }

    $notice = '';

    if ( isset( $_GET['delete'], $_GET['id'] ) ) {
        $id = (int) $_GET['id'];
        yourls_verify_nonce( 'modern_auth_delete_user_' . $id );

        $table = MODERN_AUTH_TABLE;
        $ydb = yourls_get_db('write-modern_auth_delete_user');
        $deleted = $ydb->fetchAffected( "DELETE FROM `$table` WHERE `id` = :id", [ 'id' => $id ] );

        $notice = $deleted
            ? '<p class="modern-auth-success">' . yourls_esc_html__( 'User deleted.' ) . '</p>'
            : '<p class="error">' . yourls_esc_html__( 'Could not delete user (already removed?).' ) . '</p>';
    }

    $table = MODERN_AUTH_TABLE;
    $ydb = yourls_get_db('read-modern_auth_list_users');
    $users = $ydb->fetchAll( "SELECT `id`, `username`, `email`, `created_at` FROM `$table` ORDER BY `created_at` DESC" );

    echo '<h2>' . yourls_esc_html__( 'Self-registered users' ) . '</h2>';
    echo $notice;
    echo '<p>' . yourls_esc_html__( 'Accounts created via the public registration page (/register.php). This does not include the admin account(s) defined in your config.php.' ) . '</p>';

    if ( !$users ) {
        echo '<p>' . yourls_esc_html__( 'No self-registered users yet.' ) . '</p>';
        return;
    }

    echo '<div class="modern-card" style="max-width:800px;"><table class="tblSorter" style="width:100%;"><thead><tr>';
    echo '<th>' . yourls_esc_html__( 'Username' ) . '</th>';
    echo '<th>' . yourls_esc_html__( 'Email' ) . '</th>';
    echo '<th>' . yourls_esc_html__( 'Registered' ) . '</th>';
    echo '<th>' . yourls_esc_html__( 'Actions' ) . '</th>';
    echo '</tr></thead><tbody>';

    foreach ( $users as $user ) {
        $delete_url = yourls_nonce_url(
            'modern_auth_delete_user_' . $user['id'],
            yourls_add_query_arg( [ 'page' => 'modern_auth_users', 'delete' => 1, 'id' => $user['id'] ], yourls_admin_url( 'plugins.php' ) )
        );

        echo '<tr>';
        echo '<td>' . yourls_esc_html( $user['username'] ) . '</td>';
        echo '<td>' . yourls_esc_html( $user['email'] ) . '</td>';
        echo '<td>' . yourls_esc_html( yourls_date_i18n( yourls_get_datetime_format( yourls__( 'M d, Y H:i' ) ), yourls_get_timestamp( strtotime( $user['created_at'] ) ) ) ) . '</td>';
        echo '<td><a href="' . yourls_esc_attr( $delete_url ) . '" class="button" onclick="return confirm(' . "'" . yourls_esc_js( yourls_s( 'Delete user %s? This cannot be undone.', $user['username'] ) ) . "'" . ')">' . yourls_esc_html__( 'Delete' ) . '</a></td>';
        echo '</tr>';
    }

    echo '</tbody></table></div>';
}

/**
 * ===========================================================================
 * Per-user link ownership (full isolation).
 *
 * YOURLS core keeps all short links in one table with no notion of "who created
 * this link", so with multi-user login enabled every logged-in user could see,
 * edit and delete every other user's links. This section records an owner for
 * each link and scopes all management operations to the current user:
 *   - the admin links list only shows your own links
 *   - edit / delete / edit-form / stats-page are blocked for links you don't own
 *   - the "does this long URL already exist" check is scoped to your own links,
 *     so two users shortening the same URL each get their own short link
 *   - the dashboard/overview counts reflect only your own links
 *
 * Public short-URL *redirects* are deliberately NOT restricted -- a short link
 * must resolve for anyone who clicks it, that's the whole point.
 *
 * Ownership is stored in a side table (keyword -> owner username) rather than by
 * altering the core url table, so nothing in core needs to change. "owner" is
 * the YOURLS_USER string, which is set uniformly for both config.php admins and
 * DB-registered users.
 * ===========================================================================
 */

define( 'MODERN_AUTH_OWNERS_TABLE', YOURLS_DB_PREFIX . 'link_owners' );

// Bump this whenever a new migration is added below (eg a new column). The schema-version
// option is checked BEFORE the one-time backfill-ready flag, so on installs that already ran
// modern_auth_owners_ready (activated before this version existed), the new column-check migration
// still runs -- unlike a single ready-flag, which would permanently skip it. Real bug this fixes:
// suspended/suspended_at were silently never added on any install that had already backfilled.
define( 'MODERN_AUTH_OWNERS_SCHEMA_VERSION', 2 );

/**
 * Create/migrate the ownership table, and (once ever) backfill: every pre-existing link that has
 * no owner yet is assigned to the first admin defined in config.php.
 */
yourls_add_action( 'plugins_loaded', 'modern_auth_maybe_create_owners_table' );
function modern_auth_maybe_create_owners_table() {
    if ( (int) yourls_get_option( 'modern_auth_owners_schema_version', 0 ) >= MODERN_AUTH_OWNERS_SCHEMA_VERSION ) {
        return;
    }

    $table     = MODERN_AUTH_OWNERS_TABLE;
    $url_table = YOURLS_DB_TABLE_URL;
    $pdo = yourls_get_db('write-modern_auth_create_owners')->getPdo();

    // keyword collation matches the core url table (utf8mb4_bin) so the IN (...) subqueries
    // below compare and index correctly.
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS `$table` (
            `keyword` VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
            `owner` VARCHAR(190) NOT NULL,
            `suspended` TINYINT(1) UNSIGNED NOT NULL DEFAULT 0,
            `suspended_at` DATETIME NULL,
            PRIMARY KEY (`keyword`),
            KEY `owner` (`owner`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
    );

    // Migration for tables created before the moderation (suspend) feature existed.
    modern_auth_add_column_if_missing( $pdo, $table, 'suspended', 'TINYINT(1) UNSIGNED NOT NULL DEFAULT 0' );
    modern_auth_add_column_if_missing( $pdo, $table, 'suspended_at', 'DATETIME NULL' );

    if ( !yourls_get_option( 'modern_auth_owners_ready' ) ) {
        $admin = modern_auth_first_config_admin();
        if ( $admin !== null && $admin !== '' ) {
            $stmt = $pdo->prepare(
                "INSERT IGNORE INTO `$table` (`keyword`, `owner`)
                 SELECT u.`keyword`, :admin FROM `$url_table` u
                 LEFT JOIN `$table` o ON o.`keyword` = u.`keyword`
                 WHERE o.`keyword` IS NULL"
            );
            $stmt->execute( [ 'admin' => $admin ] );
        }
        yourls_update_option( 'modern_auth_owners_ready', true );
    }

    yourls_update_option( 'modern_auth_owners_schema_version', MODERN_AUTH_OWNERS_SCHEMA_VERSION );
}

/**
 * ===========================================================================
 * Tags.
 *
 * A shared login is often really several people (or several campaigns) using
 * one account, and t.ly-style free-text tags are how they tell their own
 * links apart -- eg "kiki twitter" vs "kiki telegram" -- without needing a
 * separate account per person. Tags are plain strings, many-to-many with a
 * link (`keyword`, `tag`); no separate "tag catalog" table is needed since
 * the suggestion list is just the current owner's own distinct tags.
 *
 * Scoped implicitly through ownership: a tag row is only ever looked up
 * together with (or after already having verified) the owning keyword, so
 * there's no separate per-tag access check to get wrong.
 * ===========================================================================
 */

define( 'MODERN_AUTH_TAGS_TABLE', YOURLS_DB_PREFIX . 'link_tags' );
define( 'MODERN_AUTH_TAGS_SCHEMA_VERSION', 1 );

yourls_add_action( 'plugins_loaded', 'modern_auth_maybe_create_tags_table' );
function modern_auth_maybe_create_tags_table() {
    if ( (int) yourls_get_option( 'modern_auth_tags_schema_version', 0 ) >= MODERN_AUTH_TAGS_SCHEMA_VERSION ) {
        return;
    }

    $table = MODERN_AUTH_TAGS_TABLE;
    $pdo = yourls_get_db('write-modern_auth_create_tags')->getPdo();
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS `$table` (
            `keyword` VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
            `tag` VARCHAR(100) NOT NULL,
            PRIMARY KEY (`keyword`, `tag`),
            KEY `tag` (`tag`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
    );

    yourls_update_option( 'modern_auth_tags_schema_version', MODERN_AUTH_TAGS_SCHEMA_VERSION );
}

/**
 * @param string $keyword
 * @return string[] tags for this keyword, alphabetically
 */
function modern_auth_get_tags_for_keyword( string $keyword ): array {
    $table = MODERN_AUTH_TAGS_TABLE;
    return yourls_get_db('read-modern_auth_get_tags')->fetchCol(
        "SELECT `tag` FROM `$table` WHERE `keyword` = :keyword ORDER BY `tag` ASC",
        [ 'keyword' => yourls_sanitize_keyword( $keyword ) ]
    );
}

/**
 * @return string[] every distinct tag used across the current user's own links, alphabetically
 *                   -- the suggestion list for the "add a tag" input and the filter dropdown.
 */
function modern_auth_get_user_tags(): array {
    $owner = modern_auth_current_owner();
    if ( $owner === null ) {
        return [];
    }
    $tags_table   = MODERN_AUTH_TAGS_TABLE;
    $owners_table = MODERN_AUTH_OWNERS_TABLE;
    return yourls_get_db('read-modern_auth_user_tags')->fetchCol(
        "SELECT DISTINCT t.`tag` FROM `$tags_table` t
         INNER JOIN `$owners_table` o ON o.`keyword` = t.`keyword`
         WHERE o.`owner` = :owner ORDER BY t.`tag` ASC",
        [ 'owner' => $owner ]
    );
}

/**
 * Sanitize and normalize a raw comma-separated tags string from user input: trim, drop empties,
 * cap length, dedupe case-insensitively (first casing wins), cap count so one link can't
 * accumulate an unbounded tag list.
 *
 * @param string $raw
 * @return string[]
 */
function modern_auth_parse_tags( string $raw ): array {
    $tags = [];
    foreach ( explode( ',', $raw ) as $piece ) {
        $tag = trim( preg_replace( '/\s+/', ' ', $piece ) );
        if ( $tag === '' ) {
            continue;
        }
        $tag = mb_substr( $tag, 0, 100 );
        $key = mb_strtolower( $tag );
        if ( !isset( $tags[ $key ] ) ) {
            $tags[ $key ] = $tag;
        }
        if ( count( $tags ) >= 20 ) {
            break;
        }
    }
    return array_values( $tags );
}

/**
 * Replace the full tag set for a keyword. Caller must already have verified ownership.
 *
 * @param string   $keyword
 * @param string[] $tags
 */
function modern_auth_set_tags( string $keyword, array $tags ): void {
    $keyword = yourls_sanitize_keyword( $keyword );
    $table = MODERN_AUTH_TAGS_TABLE;
    $ydb = yourls_get_db('write-modern_auth_set_tags');
    $ydb->fetchAffected( "DELETE FROM `$table` WHERE `keyword` = :keyword", [ 'keyword' => $keyword ] );
    foreach ( $tags as $tag ) {
        $ydb->fetchAffected(
            "INSERT IGNORE INTO `$table` (`keyword`, `tag`) VALUES (:keyword, :tag)",
            [ 'keyword' => $keyword, 'tag' => $tag ]
        );
    }
}

/**
 * Render a link's tags as small pills, plus an "edit" button that assets/tags.js turns into a
 * popup (same interaction pattern as the QR code popup).
 */
function modern_auth_render_tags_cell( string $keyword ): string {
    $tags  = modern_auth_get_tags_for_keyword( $keyword );
    $nonce = yourls_create_nonce( 'modern_auth_set_tags_' . $keyword );

    $html = '<div class="modern-tags-cell" data-keyword="' . yourls_esc_attr( $keyword ) . '" data-nonce="' . yourls_esc_attr( $nonce ) . '" data-tags="' . yourls_esc_attr( implode( ', ', $tags ) ) . '">';
    foreach ( $tags as $tag ) {
        $html .= '<span class="modern-tag-pill">' . yourls_esc_html( $tag ) . '</span>';
    }
    $html .= '<button type="button" class="modern-tags-edit" title="' . yourls_esc_attr__( 'Edit tags' ) . '">+</button>';
    $html .= '</div>';
    return $html;
}

/**
 * AJAX endpoint (admin-ajax.php?action=modern_auth_set_tags) backing the tags popup. Only the
 * keyword's owner may retag it -- moderation (admin) doesn't get a bypass here, tags are purely
 * an organizational tool for the owner, not something that needs admin override.
 */
yourls_add_action( 'yourls_ajax_modern_auth_set_tags', 'modern_auth_ajax_set_tags' );
function modern_auth_ajax_set_tags() {
    $keyword = yourls_sanitize_keyword( (string) ( $_REQUEST['keyword'] ?? '' ) );
    yourls_verify_nonce( 'modern_auth_set_tags_' . $keyword, $_REQUEST['nonce'] ?? '', false, 'omg error' );

    if ( $keyword === '' || !modern_auth_owns_keyword( $keyword ) ) {
        echo json_encode( [ 'success' => false, 'message' => yourls__( 'You do not own this link.' ) ] );
        return;
    }

    $tags = modern_auth_parse_tags( (string) ( $_REQUEST['tags'] ?? '' ) );
    modern_auth_set_tags( $keyword, $tags );

    echo json_encode( [ 'success' => true, 'tags' => $tags, 'html' => modern_auth_render_tags_cell( $keyword ) ] );
}

/**
 * Extra filter bar: "Filter by tag" (reads/writes the `modern_tag` query param picked up by
 * modern_auth_filter_list_by_owner() below) plus the shared <datalist> of the user's own tags
 * that assets/tags.js points every per-row tag input at. Rendered alongside the bulk toolbar --
 * same priority-1 hook, so it's outside the buffered <table>.
 */
yourls_add_action( 'admin_page_before_table', 'modern_auth_tag_filter_bar', 1 );
function modern_auth_tag_filter_bar() {
    if ( !yourls_is_admin() ) {
        return;
    }
    $tags = modern_auth_get_user_tags();
    if ( !$tags ) {
        return;
    }
    $current = isset( $_GET['modern_tag'] ) ? (string) $_GET['modern_tag'] : '';

    echo '<div class="modern-bulk-toolbar" id="modern-tag-filter">';
    echo '<label for="modern-tag-select">' . yourls_esc_html__( 'Filter by tag' ) . '</label> ';
    echo '<select id="modern-tag-select">';
    echo '<option value="">' . yourls_esc_html__( 'All tags' ) . '</option>';
    foreach ( $tags as $tag ) {
        echo '<option value="' . yourls_esc_attr( $tag ) . '"' . ( $tag === $current ? ' selected' : '' ) . '>' . yourls_esc_html( $tag ) . '</option>';
    }
    echo '</select>';
    if ( $current !== '' ) {
        echo ' <a href="' . yourls_esc_attr( yourls_admin_url( 'index.php' ) ) . '" class="button">' . yourls_esc_html__( 'Clear' ) . '</a>';
    }
    echo '</div>';

    echo '<datalist id="modern-tags-datalist">';
    foreach ( $tags as $tag ) {
        echo '<option value="' . yourls_esc_attr( $tag ) . '">';
    }
    echo '</datalist>';
}

/**
 * @return string|null first username defined in config.php's $yourls_user_passwords, or null
 */
function modern_auth_first_config_admin() {
    $users = $GLOBALS['yourls_user_passwords'] ?? [];
    if ( !is_array( $users ) || !$users ) {
        return null;
    }
    return (string) array_key_first( $users );
}

/**
 * @return string|null the current logged-in username, or null if none
 */
function modern_auth_current_owner() {
    return defined( 'YOURLS_USER' ) ? (string) YOURLS_USER : null;
}

/**
 * @param string $keyword
 * @return bool whether the current user owns this keyword. Fails closed: unknown/un-owned
 *              keywords and anonymous requests return false.
 */
function modern_auth_owns_keyword( $keyword ) {
    $owner = modern_auth_current_owner();
    if ( $owner === null ) {
        return false;
    }
    $table = MODERN_AUTH_OWNERS_TABLE;
    $found = yourls_get_db('read-modern_auth_owns')->fetchValue(
        "SELECT `owner` FROM `$table` WHERE `keyword` = :keyword LIMIT 1",
        [ 'keyword' => yourls_sanitize_keyword( $keyword ) ]
    );
    return ( $found !== false && $found !== null && (string) $found === $owner );
}

/**
 * Record ownership when a link is created. insert_link fires as
 * do_action('insert_link', $success, $url, $keyword, $title, $timestamp, $ip); YOURLS passes
 * all action arguments to callbacks as a single array (see note on modern_auth_admin_assets).
 */
yourls_add_action( 'insert_link', 'modern_auth_record_owner' );
function modern_auth_record_owner( $args ) {
    if ( !is_array( $args ) ) {
        return;
    }
    $success = $args[0] ?? false;
    $keyword = $args[2] ?? '';
    if ( !$success || $keyword === '' || !defined( 'YOURLS_USER' ) ) {
        return;
    }
    $table = MODERN_AUTH_OWNERS_TABLE;
    yourls_get_db('write-modern_auth_record_owner')->fetchAffected(
        "REPLACE INTO `$table` (`keyword`, `owner`) VALUES (:keyword, :owner)",
        [ 'keyword' => $keyword, 'owner' => YOURLS_USER ]
    );
}

/**
 * Restrict the admin links list to the current user's own links, and further to a single tag
 * when ?modern_tag=... is present (see modern_auth_tag_filter_bar() above).
 */
yourls_add_filter( 'admin_list_where', 'modern_auth_filter_list_by_owner' );
function modern_auth_filter_list_by_owner( $where ) {
    $owner = modern_auth_current_owner();
    if ( $owner === null ) {
        $where['sql'] .= ' AND 1=0';
        return $where;
    }
    $table = MODERN_AUTH_OWNERS_TABLE;
    $where['sql'] .= " AND `keyword` IN (SELECT `keyword` FROM `$table` WHERE `owner` = :modern_auth_owner)";
    $where['binds']['modern_auth_owner'] = $owner;

    if ( !empty( $_GET['modern_tag'] ) ) {
        $tags_table = MODERN_AUTH_TAGS_TABLE;
        $where['sql'] .= " AND `keyword` IN (SELECT `keyword` FROM `$tags_table` WHERE `tag` = :modern_auth_tag)";
        $where['binds']['modern_auth_tag'] = mb_substr( (string) $_GET['modern_tag'], 0, 100 );
    }

    return $where;
}

/**
 * Scope db stats (total links / clicks shown on the dashboard) to the current user.
 */
yourls_add_filter( 'get_db_stats', 'modern_auth_filter_db_stats', 10, 2 );
function modern_auth_filter_db_stats( $return, $where ) {
    $owner = modern_auth_current_owner();
    if ( $owner === null ) {
        return [ 'total_links' => 0, 'total_clicks' => 0 ];
    }
    $url_table    = YOURLS_DB_TABLE_URL;
    $owners_table = MODERN_AUTH_OWNERS_TABLE;
    $sql = "SELECT COUNT(keyword) AS count, SUM(clicks) AS sum FROM `$url_table` WHERE 1=1 "
         . ( $where['sql'] ?? '' )
         . " AND `keyword` IN (SELECT `keyword` FROM `$owners_table` WHERE `owner` = :modern_auth_owner)";
    $binds = ( $where['binds'] ?? [] );
    $binds['modern_auth_owner'] = $owner;
    $totals = yourls_get_db('read-modern_auth_db_stats')->fetchObject( $sql, $binds );
    return [ 'total_links' => (int) $totals->count, 'total_clicks' => (int) ( $totals->sum ?? 0 ) ];
}

/**
 * Block deleting a link you don't own (returns 0 rows affected -> ajax reports failure).
 * Admin moderation actions (see "Admin moderation" section below) set
 * $GLOBALS['modern_auth_moderation_override'] right before calling the core delete function,
 * so the config-admin can delete ANY link from the "All Links" page, not just their own.
 */
yourls_add_filter( 'shunt_delete_link_by_keyword', 'modern_auth_guard_delete', 10, 2 );
function modern_auth_guard_delete( $default, $keyword ) {
    if ( !empty( $GLOBALS['modern_auth_moderation_override'] ) ) {
        return $default;
    }
    return modern_auth_owns_keyword( $keyword ) ? $default : 0;
}

/**
 * Whenever a link is actually deleted (by its owner, or by admin moderation), drop its
 * ownership/suspension AND tags rows too so neither table accumulates orphaned entries.
 * delete_link fires as do_action('delete_link', $keyword, $delete) -- array-wrapped, as usual.
 */
yourls_add_action( 'delete_link', 'modern_auth_cleanup_owner_on_delete' );
function modern_auth_cleanup_owner_on_delete( $args ) {
    $keyword = is_array( $args ) ? ( $args[0] ?? '' ) : '';
    if ( $keyword === '' ) {
        return;
    }
    $tags_table = MODERN_AUTH_TAGS_TABLE;
    yourls_get_db('write-modern_auth_cleanup_tags')->fetchAffected(
        "DELETE FROM `$tags_table` WHERE `keyword` = :keyword",
        [ 'keyword' => $keyword ]
    );
    $table = MODERN_AUTH_OWNERS_TABLE;
    yourls_get_db('write-modern_auth_cleanup_owner')->fetchAffected(
        "DELETE FROM `$table` WHERE `keyword` = :keyword",
        [ 'keyword' => $keyword ]
    );
}

/**
 * Block saving edits to a link you don't own.
 */
yourls_add_filter( 'shunt_edit_link', 'modern_auth_guard_edit', 10, 2 );
function modern_auth_guard_edit( $default, $keyword ) {
    if ( modern_auth_owns_keyword( $keyword ) ) {
        return $default;
    }
    return [
        'status'     => 'fail',
        'code'       => 'error:owner',
        'message'    => yourls__( 'You do not own this link.' ),
        'errorCode'  => '403',
    ];
}

/**
 * Block the inline edit *form* for a link you don't own (it would otherwise reveal the
 * target URL). Replaces the row HTML with an error notice.
 */
yourls_add_filter( 'table_edit_row', 'modern_auth_guard_edit_row', 10, 2 );
function modern_auth_guard_edit_row( $html, $keyword ) {
    if ( modern_auth_owns_keyword( $keyword ) ) {
        return $html;
    }
    return '<tr class="edit-row notfound"><td colspan="6" class="edit-row notfound">'
         . yourls_esc_html__( 'You do not own this link.' ) . '</td></tr>';
}

/**
 * Block the per-link stats page (keyword+) for links you don't own. Only applies to logged-in
 * requests -- anonymous access is already governed by YOURLS_PRIVATE, and public redirects are
 * never affected (this is the stats page, not the redirect).
 */
yourls_add_action( 'pre_yourls_infos', 'modern_auth_guard_infos' );
function modern_auth_guard_infos( $keyword ) {
    if ( !defined( 'YOURLS_USER' ) ) {
        return;
    }
    $keyword = is_array( $keyword ) ? ( $keyword[0] ?? '' ) : $keyword;
    if ( modern_auth_owns_keyword( $keyword ) ) {
        return;
    }
    yourls_redirect( yourls_admin_url( 'index.php' ), 302 );
    exit;
}

/**
 * Never treat a URL as "already shortened" for a logged-in user -- always let them create a new
 * short link for it, even one they've shortened before. This is what makes it possible to make
 * several short links for the same destination on purpose, eg one per channel (a Facebook post,
 * a tweet, a newsletter) so clicks from each can be told apart in the stats. Core's own
 * duplicate-URL prevention (YOURLS_UNIQUE_URLS) assumes a single owner for the whole site; under
 * per-user isolation that would only ever compare a link against the current user's own past
 * links anyway, so disabling it here (rather than telling every site owner to also flip
 * YOURLS_UNIQUE_URLS to false in config.php) is the more faithful fix. No-user contexts (eg CLI,
 * install) are unaffected -- $default proceeds as core would run it.
 */
yourls_add_filter( 'shunt_url_exists', 'modern_auth_scope_url_exists', 10, 2 );
function modern_auth_scope_url_exists( $default, $url ) {
    if ( modern_auth_current_owner() === null ) {
        return $default; // no user context (eg CLI/install): let core behave normally
    }
    return null; // "not found" -> yourls_add_new_link() always creates a new short link
}

/**
 * ===========================================================================
 * Admin capability separation.
 *
 * YOURLS core has no roles: anyone who can log into /admin/ has full control,
 * including managing plugins and tools. With self-registration enabled that
 * means a regular user could open "Manage Plugins" and DEACTIVATE this very
 * plugin -- which would silently remove all the ownership isolation above.
 *
 * So: restrict the admin-management pages (plugins.php, tools.php) to the
 * admin account(s) defined in config.php. Regular DB users keep the links
 * dashboard, their own link management (admin-ajax), and stats for their own
 * links -- everything they need, nothing that can affect other users or the
 * plugin. Enforced on 'auth_successful', which fires on every admin page right
 * after login and before the page acts on the request (including before
 * plugins.php processes an activate/deactivate), so it blocks the action too,
 * not just the view.
 * ===========================================================================
 */

/**
 * @return bool whether the current user is an admin defined in config.php (vs a DB user)
 */
function modern_auth_is_config_admin() {
    if ( !defined( 'YOURLS_USER' ) ) {
        return false;
    }
    $admins = array_keys( (array) ( $GLOBALS['yourls_user_passwords'] ?? [] ) );
    return in_array( (string) YOURLS_USER, $admins, true );
}

yourls_add_action( 'auth_successful', 'modern_auth_enforce_admin_capability' );
function modern_auth_enforce_admin_capability() {
    if ( modern_auth_is_config_admin() ) {
        return; // config admins keep full access
    }
    $script = basename( (string) ( $_SERVER['SCRIPT_NAME'] ?? '' ) );
    $admin_only = yourls_apply_filter( 'modern_auth_admin_only_scripts', [ 'plugins.php', 'tools.php' ] );
    if ( in_array( $script, $admin_only, true ) ) {
        yourls_die(
            yourls__( 'You do not have permission to access this page.' ),
            yourls__( 'Access denied' ),
            403
        );
    }
}

/**
 * Hide the admin-management menu entries (Tools, Manage Plugins and its sub-pages) from
 * regular users, so they don't see links they can't use. The auth_successful guard above is
 * what actually enforces access; this just keeps the menu honest.
 */
yourls_add_filter( 'admin_links', 'modern_auth_filter_admin_links' );
function modern_auth_filter_admin_links( $links ) {
    if ( modern_auth_is_config_admin() ) {
        return $links;
    }
    unset( $links['tools'], $links['plugins'] );
    return $links;
}

yourls_add_filter( 'admin_sublinks', 'modern_auth_filter_admin_sublinks' );
function modern_auth_filter_admin_sublinks( $sublinks ) {
    if ( modern_auth_is_config_admin() ) {
        return $sublinks;
    }
    unset( $sublinks['plugins'] );
    return $sublinks;
}

/**
 * ===========================================================================
 * Admin moderation: "All Links".
 *
 * Per-user isolation (above) is intentionally total: not even the config
 * admin sees other users' links on the normal dashboard. But the admin still
 * needs a way to act on abuse -- a spam or malicious link someone else
 * created -- without that turning into "admin can browse everyone's links".
 *
 * So this is a deliberately narrow, separate capability: a single admin-only
 * page listing every link with its owner, offering exactly two actions,
 * suspend and delete. Suspending blocks the public redirect (410) without
 * touching data; deleting removes the link outright. Both bypass the
 * ownership guard via $GLOBALS['modern_auth_moderation_override'] (checked
 * in modern_auth_guard_delete() above), scoped to just this page's request.
 *
 * Registered as a plugin page, same mechanism as "Manage Users" -- which
 * means it's already covered by modern_auth_enforce_admin_capability()
 * blocking all of plugins.php for non-config-admins, and already hidden
 * from the menu by modern_auth_filter_admin_sublinks() above.
 * ===========================================================================
 */

/**
 * @param string $keyword
 * @return bool
 */
function modern_auth_is_suspended( string $keyword ): bool {
    $table = MODERN_AUTH_OWNERS_TABLE;
    $val = yourls_get_db('read-modern_auth_is_suspended')->fetchValue(
        "SELECT `suspended` FROM `$table` WHERE `keyword` = :keyword LIMIT 1",
        [ 'keyword' => yourls_sanitize_keyword( $keyword ) ]
    );
    return ( $val !== false && $val !== null && (int) $val === 1 );
}

/**
 * Suspend or reactivate a link. Uses an upsert so this still works even for the unlikely edge
 * case of a link with no owners-table row yet; ON DUPLICATE KEY UPDATE never touches `owner`,
 * so an existing owner is always preserved.
 */
function modern_auth_set_suspended( string $keyword, bool $suspended ): void {
    $table = MODERN_AUTH_OWNERS_TABLE;
    yourls_get_db('write-modern_auth_set_suspended')->fetchAffected(
        "INSERT INTO `$table` (`keyword`, `owner`, `suspended`, `suspended_at`)
         VALUES (:keyword, '', :suspended, :suspended_at)
         ON DUPLICATE KEY UPDATE `suspended` = VALUES(`suspended`), `suspended_at` = VALUES(`suspended_at`)",
        [
            'keyword'      => yourls_sanitize_keyword( $keyword ),
            'suspended'    => $suspended ? 1 : 0,
            'suspended_at' => $suspended ? date( 'Y-m-d H:i:s' ) : null,
        ]
    );
}

/**
 * Block the public redirect for a suspended link. Hooked on 'load_template_go', which fires in
 * yourls-loader.php right before it requires yourls-go.php (the file that actually issues the
 * redirect) -- so this runs early enough to intercept it, for both plain keywords and pages.
 * Deliberately does NOT touch the stats page (pre_yourls_infos) -- the owner can still see their
 * own suspended link's stats, just can't have it redirect publicly.
 */
yourls_add_action( 'load_template_go', 'modern_auth_block_suspended_redirect' );
function modern_auth_block_suspended_redirect( $keyword ) {
    $keyword = is_array( $keyword ) ? ( $keyword[0] ?? '' ) : $keyword;
    if ( $keyword === '' || !modern_auth_is_suspended( (string) $keyword ) ) {
        return;
    }
    yourls_die(
        yourls__( 'This link has been suspended by the site administrator and is no longer available.' ),
        yourls__( 'Link suspended' ),
        410
    );
}

yourls_add_action( 'plugins_loaded', 'modern_auth_register_links_page' );
function modern_auth_register_links_page() {
    yourls_register_plugin_page( 'modern_auth_links', yourls__( 'All Links' ), 'modern_auth_links_page' );
}

function modern_auth_links_page() {
    // Defense in depth: this page is reached via plugins.php, which the auth_successful guard
    // already restricts to config admins -- but never render moderation for anyone else.
    if ( !modern_auth_is_config_admin() ) {
        yourls_die( yourls__( 'You do not have permission to access this page.' ), yourls__( 'Access denied' ), 403 );
    }

    $notice   = '';
    $base_url = yourls_add_query_arg( [ 'page' => 'modern_auth_links' ], yourls_admin_url( 'plugins.php' ) );

    // Single-row action: ?linkaction=suspend|unsuspend|delete&keyword=...&nonce=...
    if ( isset( $_GET['linkaction'], $_GET['keyword'] ) ) {
        $linkaction = (string) $_GET['linkaction'];
        $keyword    = yourls_sanitize_keyword( (string) $_GET['keyword'] );
        yourls_verify_nonce( 'modern_auth_link_action_' . $linkaction . '_' . $keyword );

        if ( $linkaction === 'suspend' ) {
            modern_auth_set_suspended( $keyword, true );
            $notice = '<p class="modern-auth-success">' . yourls_esc_html__( 'Link suspended.' ) . '</p>';
        } elseif ( $linkaction === 'unsuspend' ) {
            modern_auth_set_suspended( $keyword, false );
            $notice = '<p class="modern-auth-success">' . yourls_esc_html__( 'Link reactivated.' ) . '</p>';
        } elseif ( $linkaction === 'delete' ) {
            $GLOBALS['modern_auth_moderation_override'] = true;
            $deleted = yourls_delete_link_by_keyword( $keyword );
            $GLOBALS['modern_auth_moderation_override'] = false;
            $notice = $deleted
                ? '<p class="modern-auth-success">' . yourls_esc_html__( 'Link deleted.' ) . '</p>'
                : '<p class="error">' . yourls_esc_html__( 'Could not delete link (already removed?).' ) . '</p>';
        }
    }

    // Bulk action: POST modern_auth_links_bulk=1, bulk_action, keywords[]
    if ( !empty( $_POST['modern_auth_links_bulk'] ) ) {
        yourls_verify_nonce( 'modern_auth_links_bulk' );
        $bulk_action = (string) ( $_POST['bulk_action'] ?? '' );
        $keywords    = ( isset( $_POST['keywords'] ) && is_array( $_POST['keywords'] ) ) ? $_POST['keywords'] : [];
        $count = 0;
        foreach ( $keywords as $keyword ) {
            $keyword = yourls_sanitize_keyword( (string) $keyword );
            if ( $keyword === '' ) {
                continue;
            }
            if ( $bulk_action === 'suspend' ) {
                modern_auth_set_suspended( $keyword, true );
                $count++;
            } elseif ( $bulk_action === 'unsuspend' ) {
                modern_auth_set_suspended( $keyword, false );
                $count++;
            } elseif ( $bulk_action === 'delete' ) {
                $GLOBALS['modern_auth_moderation_override'] = true;
                if ( yourls_delete_link_by_keyword( $keyword ) ) {
                    $count++;
                }
                $GLOBALS['modern_auth_moderation_override'] = false;
            }
        }
        $notice = '<p class="modern-auth-success">' . yourls_esc_html( sprintf( yourls__( 'Applied to %d link(s).' ), $count ) ) . '</p>';
    }

    $url_table    = YOURLS_DB_TABLE_URL;
    $owners_table = MODERN_AUTH_OWNERS_TABLE;
    $ydb = yourls_get_db('read-modern_auth_list_links');
    $links = $ydb->fetchAll(
        "SELECT u.`keyword`, u.`url`, u.`clicks`, u.`timestamp`, o.`owner`, o.`suspended`
         FROM `$url_table` u
         LEFT JOIN `$owners_table` o ON o.`keyword` = u.`keyword`
         ORDER BY u.`timestamp` DESC
         LIMIT 300"
    );

    echo '<h2>' . yourls_esc_html__( 'All links' ) . '</h2>';
    echo $notice;
    echo '<p>' . yourls_esc_html__( 'Every link on this server, across all users. Suspend a link to block its public redirect without deleting it, or delete it outright. This view (and these actions) are only available to the admin account(s) defined in config.php -- regular users only ever see and manage their own links.' ) . '</p>';

    if ( count( $links ) >= 300 ) {
        echo '<p><em>' . yourls_esc_html__( 'Showing the 300 most recent links.' ) . '</em></p>';
    }

    if ( !$links ) {
        echo '<p>' . yourls_esc_html__( 'No links yet.' ) . '</p>';
        return;
    }

    echo '<form method="post" action="' . yourls_esc_attr( $base_url ) . '">';
    yourls_nonce_field( 'modern_auth_links_bulk' );
    echo '<input type="hidden" name="modern_auth_links_bulk" value="1" />';

    echo '<div class="modern-bulk-toolbar">';
    echo '<select name="bulk_action">';
    echo '<option value="suspend">' . yourls_esc_html__( 'Suspend selected' ) . '</option>';
    echo '<option value="unsuspend">' . yourls_esc_html__( 'Reactivate selected' ) . '</option>';
    echo '<option value="delete">' . yourls_esc_html__( 'Delete selected' ) . '</option>';
    echo '</select> ';
    echo '<input type="submit" class="button" value="' . yourls_esc_attr__( 'Apply' ) . '" onclick="return confirm(' . "'" . yourls_esc_js( yourls__( 'Apply this action to all selected links?' ) ) . "'" . ')" />';
    echo '</div>';

    echo '<div class="modern-card" style="max-width:100%;overflow-x:auto;"><table class="tblSorter" style="width:100%;"><thead><tr>';
    echo '<th><input type="checkbox" onclick="document.querySelectorAll(\'.modern-links-select\').forEach(function(c){c.checked=this.checked;}, this)" /></th>';
    echo '<th>' . yourls_esc_html__( 'Short URL' ) . '</th>';
    echo '<th>' . yourls_esc_html__( 'Destination' ) . '</th>';
    echo '<th>' . yourls_esc_html__( 'Owner' ) . '</th>';
    echo '<th>' . yourls_esc_html__( 'Tags' ) . '</th>';
    echo '<th>' . yourls_esc_html__( 'Clicks' ) . '</th>';
    echo '<th>' . yourls_esc_html__( 'Created' ) . '</th>';
    echo '<th>' . yourls_esc_html__( 'Status' ) . '</th>';
    echo '<th>' . yourls_esc_html__( 'Actions' ) . '</th>';
    echo '</tr></thead><tbody>';

    foreach ( $links as $link ) {
        $keyword   = $link['keyword'];
        $suspended = !empty( $link['suspended'] );
        $owner     = ( $link['owner'] !== null && $link['owner'] !== '' ) ? $link['owner'] : yourls__( 'Unknown' );

        $suspend_action = $suspended ? 'unsuspend' : 'suspend';
        $suspend_label  = $suspended ? yourls__( 'Reactivate' ) : yourls__( 'Suspend' );
        $suspend_url = yourls_nonce_url(
            'modern_auth_link_action_' . $suspend_action . '_' . $keyword,
            yourls_add_query_arg( [ 'linkaction' => $suspend_action, 'keyword' => $keyword ], $base_url )
        );
        $delete_url = yourls_nonce_url(
            'modern_auth_link_action_delete_' . $keyword,
            yourls_add_query_arg( [ 'linkaction' => 'delete', 'keyword' => $keyword ], $base_url )
        );

        echo '<tr>';
        echo '<td><input type="checkbox" class="modern-links-select" name="keywords[]" value="' . yourls_esc_attr( $keyword ) . '" /></td>';
        echo '<td><a href="' . yourls_esc_attr( yourls_link( $keyword ) ) . '" target="_blank" rel="noopener">' . yourls_esc_html( yourls_link( $keyword ) ) . '</a></td>';
        echo '<td title="' . yourls_esc_attr( $link['url'] ) . '">' . yourls_esc_html( yourls_trim_long_string( $link['url'], 60 ) ) . '</td>';
        echo '<td>' . yourls_esc_html( $owner ) . '</td>';
        $tags = modern_auth_get_tags_for_keyword( $keyword );
        echo '<td>' . ( $tags ? implode( ' ', array_map( static function ( $tag ) {
            return '<span class="modern-tag-pill">' . yourls_esc_html( $tag ) . '</span>';
        }, $tags ) ) : '' ) . '</td>';
        echo '<td>' . yourls_number_format_i18n( $link['clicks'] ) . '</td>';
        echo '<td>' . yourls_esc_html( yourls_date_i18n( yourls_get_datetime_format( yourls__( 'M d, Y H:i' ) ), yourls_get_timestamp( strtotime( $link['timestamp'] ) ) ) ) . '</td>';
        echo '<td>' . ( $suspended
            ? '<span class="modern-badge modern-badge-danger">' . yourls_esc_html__( 'Suspended' ) . '</span>'
            : '<span class="modern-badge modern-badge-ok">' . yourls_esc_html__( 'Active' ) . '</span>' ) . '</td>';
        echo '<td>';
        echo '<a href="' . yourls_esc_attr( $suspend_url ) . '" class="button">' . yourls_esc_html( $suspend_label ) . '</a> ';
        echo '<a href="' . yourls_esc_attr( $delete_url ) . '" class="button" onclick="return confirm(' . "'" . yourls_esc_js( yourls_s( 'Delete link %s? This cannot be undone.', $keyword ) ) . "'" . ')">' . yourls_esc_html__( 'Delete' ) . '</a>';
        echo '</td>';
        echo '</tr>';
    }

    echo '</tbody></table></div>';
    echo '</form>';
}

/**
 * ===========================================================================
 * Advanced analytics: city-level location, device/browser breakdown, and a
 * searchable "Cities" table on each link's stats page (yourls-infos.php).
 *
 * City lookups need a GeoLite2-City.mmdb database. Unlike the country-level
 * DB core already bundles (includes/geo/GeoLite2-Country.mmdb), MaxMind's
 * policy since Dec 2019 requires a free personal account + license key for
 * it, so it can't just be bundled the same way -- docker-entrypoint.sh
 * downloads it into geo/GeoLite2-City.mmdb at container start when
 * MAXMIND_LICENSE_KEY is set. If it's missing, the Cities section says so
 * plainly instead of silently doing nothing; everything else on the stats
 * page (including device/browser, which needs no extra setup) is
 * unaffected. Reuses core's already-vendored geoip2 reader library
 * (includes/vendor/geoip2), same one core's own country lookup uses.
 *
 * Ownership is already enforced by modern_auth_guard_infos() (hooked on
 * 'pre_yourls_infos', which fires before any of this) -- by the time these
 * hooks run, either the request is anonymous under a public install, or the
 * current user has already been confirmed to own this keyword.
 * ===========================================================================
 */

function modern_auth_geo_city_db_path(): string {
    return (string) yourls_apply_filter( 'modern_auth_geo_city_db_path', __DIR__ . '/geo/GeoLite2-City.mmdb' );
}

/**
 * @return \GeoIp2\Database\Reader|null cached reader, or null if the City DB isn't set up
 */
function modern_auth_geo_city_reader() {
    static $reader = null;
    static $tried = false;
    if ( $tried ) {
        return $reader;
    }
    $tried = true;

    $path = modern_auth_geo_city_db_path();
    if ( !is_readable( $path ) ) {
        return null;
    }
    try {
        $reader = new \GeoIp2\Database\Reader( $path );
    } catch ( \Exception $e ) {
        $reader = null;
    }
    return $reader;
}

/**
 * @param string $ip
 * @return array{city:string,subdivision:string,country:string}|null
 */
function modern_auth_ip_to_city( string $ip ) {
    $reader = modern_auth_geo_city_reader();
    if ( !$reader ) {
        return null;
    }
    try {
        $record = $reader->city( $ip );
        return [
            'city'        => (string) ( $record->city->name ?? '' ),
            'subdivision' => (string) ( $record->mostSpecificSubdivision->name ?? '' ),
            'country'     => (string) ( $record->country->isoCode ?? '' ),
        ];
    } catch ( \Exception $e ) {
        return null;
    }
}

/**
 * Lightweight heuristic User-Agent classifier: coarse device type + browser name from
 * the raw string already stored per click. This is deliberately approximate (real UA
 * parsing is inherently fuzzy, browsers spoof each other's tokens on purpose) -- good
 * enough for a rough breakdown, not meant to be forensically precise.
 *
 * @param string $ua
 * @return array{device:string,browser:string}
 */
function modern_auth_parse_user_agent( string $ua ): array {
    if ( trim( $ua ) === '' ) {
        return [ 'device' => yourls__( 'Unknown' ), 'browser' => yourls__( 'Unknown' ) ];
    }

    if ( preg_match( '/bot|crawl|spider|slurp|facebookexternalhit|whatsapp|telegrambot|bingpreview/i', $ua ) ) {
        $device = yourls__( 'Bot' );
    } elseif ( preg_match( '/ipad|tablet(?!.*mobile)|kindle|playbook|nexus (7|9|10)/i', $ua ) ) {
        $device = yourls__( 'Tablet' );
    } elseif ( preg_match( '/mobi|iphone|ipod|android.*mobile|blackberry|windows phone/i', $ua ) ) {
        $device = yourls__( 'Mobile' );
    } else {
        $device = yourls__( 'Desktop' );
    }

    $ua_l = strtolower( $ua );
    if ( strpos( $ua_l, 'edg/' ) !== false || strpos( $ua_l, 'edge' ) !== false ) {
        $browser = 'Edge';
    } elseif ( strpos( $ua_l, 'opr/' ) !== false || strpos( $ua_l, 'opera' ) !== false ) {
        $browser = 'Opera';
    } elseif ( strpos( $ua_l, 'firefox' ) !== false ) {
        $browser = 'Firefox';
    } elseif ( strpos( $ua_l, 'chrome' ) !== false || strpos( $ua_l, 'crios' ) !== false ) {
        $browser = 'Chrome';
    } elseif ( strpos( $ua_l, 'safari' ) !== false ) {
        $browser = 'Safari';
    } else {
        $browser = yourls__( 'Other' );
    }

    return [ 'device' => $device, 'browser' => $browser ];
}

/**
 * Render a simple label + horizontal-bar + count/percentage breakdown -- used for both
 * the Devices and Platform (browser) cards. No chart library needed.
 */
function modern_auth_render_breakdown_bars( array $data, int $total ): string {
    if ( $total <= 0 || !$data ) {
        return '<p>' . yourls_esc_html__( 'No data yet.' ) . '</p>';
    }
    $html = '<div class="modern-breakdown">';
    foreach ( $data as $label => $count ) {
        $pct = (int) round( ( $count / $total ) * 100 );
        $html .= '<div class="modern-breakdown-row">';
        $html .= '<span class="modern-breakdown-label">' . yourls_esc_html( (string) $label ) . '</span>';
        $html .= '<span class="modern-breakdown-bar"><span style="width:' . $pct . '%"></span></span>';
        $html .= '<span class="modern-breakdown-value">' . yourls_number_format_i18n( $count ) . ' (' . $pct . '%)</span>';
        $html .= '</div>';
    }
    $html .= '</div>';
    return $html;
}

/**
 * "Cities" card in the Traffic location tab: a searchable, country-filterable table of
 * cities resolved from this link's distinct visitor IPs. Hooked on 'pre_yourls_info_location'
 * (fires unconditionally whenever the tab exists) rather than 'post_yourls_info_location'
 * (which core only fires when its own country-level $countries array is non-empty) -- a
 * link can have clicks with no *country* ever resolved (eg all from local/private IPs in
 * testing) while still legitimately having nothing to show here, and this card computes
 * its own data independently of core's $countries anyway.
 */
yourls_add_action( 'pre_yourls_info_location', 'modern_auth_render_cities_section' );
function modern_auth_render_cities_section( $keyword ) {
    $keyword = is_array( $keyword ) ? ( $keyword[0] ?? '' ) : $keyword;
    if ( $keyword === '' ) {
        return;
    }

    echo '<div class="modern-card modern-analytics-card"><h3>' . yourls_esc_html__( 'Cities' ) . '</h3>';

    if ( !modern_auth_geo_city_reader() ) {
        echo '<p class="modern-analytics-hint">' . yourls_esc_html__( 'City-level data isn\'t set up on this server. Set the MAXMIND_LICENSE_KEY environment variable to enable it (see .env.example).' ) . '</p></div>';
        return;
    }

    $table = YOURLS_DB_TABLE_LOG;
    $rows = yourls_get_db('read-modern_auth_city_ips')->fetchAll(
        "SELECT `ip_address`, COUNT(*) AS `count` FROM `$table` WHERE `shorturl` = :keyword GROUP BY `ip_address`",
        [ 'keyword' => $keyword ]
    );

    $cities = [];
    foreach ( $rows as $row ) {
        $loc = modern_auth_ip_to_city( (string) $row['ip_address'] );
        if ( !$loc || $loc['city'] === '' ) {
            continue;
        }
        $key = $loc['city'] . '|' . $loc['subdivision'] . '|' . $loc['country'];
        if ( !isset( $cities[ $key ] ) ) {
            $cities[ $key ] = [ 'city' => $loc['city'], 'subdivision' => $loc['subdivision'], 'country' => $loc['country'], 'count' => 0 ];
        }
        $cities[ $key ]['count'] += (int) $row['count'];
    }

    if ( !$cities ) {
        echo '<p>' . yourls_esc_html__( 'No city data for this link yet.' ) . '</p></div>';
        return;
    }

    uasort( $cities, static function ( $a, $b ) { return $b['count'] <=> $a['count']; } );
    $countries = array_values( array_unique( array_filter( array_column( $cities, 'country' ) ) ) );
    sort( $countries );

    echo '<div class="modern-analytics-filters">';
    echo '<input type="text" id="modern-city-search" placeholder="' . yourls_esc_attr__( 'Search city...' ) . '" />';
    echo '<select id="modern-city-country"><option value="">' . yourls_esc_html__( 'All countries' ) . '</option>';
    foreach ( $countries as $code ) {
        echo '<option value="' . yourls_esc_attr( $code ) . '">' . yourls_esc_html( yourls_geo_countrycode_to_countryname( $code ) ?: $code ) . '</option>';
    }
    echo '</select></div>';

    echo '<table class="tblSorter modern-city-table" id="modern-city-table" style="width:100%;"><thead><tr>';
    echo '<th>' . yourls_esc_html__( 'City' ) . '</th>';
    echo '<th>' . yourls_esc_html__( 'Region' ) . '</th>';
    echo '<th>' . yourls_esc_html__( 'Country' ) . '</th>';
    echo '<th>' . yourls_esc_html__( 'Clicks' ) . '</th>';
    echo '</tr></thead><tbody>';
    foreach ( $cities as $c ) {
        echo '<tr data-country="' . yourls_esc_attr( $c['country'] ) . '">';
        echo '<td>' . yourls_esc_html( $c['city'] ) . '</td>';
        echo '<td>' . yourls_esc_html( $c['subdivision'] ) . '</td>';
        echo '<td>' . yourls_esc_html( yourls_geo_countrycode_to_countryname( $c['country'] ) ?: $c['country'] ) . '</td>';
        echo '<td>' . yourls_number_format_i18n( $c['count'] ) . '</td>';
        echo '</tr>';
    }
    echo '</tbody></table></div>';
}

/**
 * "Devices" and "Platform (browser)" cards in the Traffic statistics tab, parsed from
 * this link's distinct user_agent strings (grouped in SQL, parsed once per distinct
 * value rather than once per click).
 */
yourls_add_action( 'post_yourls_info_stats', 'modern_auth_render_device_section' );
function modern_auth_render_device_section( $keyword ) {
    $keyword = is_array( $keyword ) ? ( $keyword[0] ?? '' ) : $keyword;
    if ( $keyword === '' ) {
        return;
    }

    $table = YOURLS_DB_TABLE_LOG;
    $rows = yourls_get_db('read-modern_auth_ua_breakdown')->fetchAll(
        "SELECT `user_agent`, COUNT(*) AS `count` FROM `$table` WHERE `shorturl` = :keyword GROUP BY `user_agent`",
        [ 'keyword' => $keyword ]
    );
    if ( !$rows ) {
        return;
    }

    $devices = [];
    $browsers = [];
    $total = 0;
    foreach ( $rows as $row ) {
        $parsed = modern_auth_parse_user_agent( (string) $row['user_agent'] );
        $count = (int) $row['count'];
        $devices[ $parsed['device'] ]   = ( $devices[ $parsed['device'] ] ?? 0 ) + $count;
        $browsers[ $parsed['browser'] ] = ( $browsers[ $parsed['browser'] ] ?? 0 ) + $count;
        $total += $count;
    }
    arsort( $devices );
    arsort( $browsers );

    echo '<div class="modern-card modern-analytics-card"><h3>' . yourls_esc_html__( 'Devices' ) . '</h3>' . modern_auth_render_breakdown_bars( $devices, $total ) . '</div>';
    echo '<div class="modern-card modern-analytics-card"><h3>' . yourls_esc_html__( 'Platform (browser)' ) . '</h3>' . modern_auth_render_breakdown_bars( $browsers, $total ) . '</div>';
}
