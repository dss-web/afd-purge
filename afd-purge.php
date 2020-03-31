<?php declare( strict_types = 1 );
/**
 * Azure Front Door Purge
 *
 * @package     Azure Front Door Purge
 * @author      Per Soderlind
 * @copyright   2020 Per Soderlind
 * @license     GPL-2.0+
 *
 * @wordpress-plugin
 * Plugin Name: Azure Front Door Purge
 * Plugin URI: https://github.com/soderlind/afd-purge
 * GitHub Plugin URI: https://github.com/soderlind/afd-purge
 * Description: description
 * Version:     0.0.1
 * Author:      Per Soderlind
 * Author URI:  https://soderlind.no
 * Text Domain: afd-purge
 * License:     GPL-2.0+
 * License URI: http://www.gnu.org/licenses/gpl-2.0.txt
 */

namespace Soderlind\Azure\FrontDoor;

if ( ! defined('ABSPATH') ) {
	wp_die();
}

require_once 'vendor/autoload.php';

class Purge {

	public function __construct() {
		add_action('admin_menu', [ $this, 'admin_menu' ]);
	}

	public function admin_menu() {
		add_options_page('Azure Front Door', 'Azure Front Door', 'manage_options', 'options_page_slug', [ $this, 'admin_page' ]);
	}

	public function azure_authenticate( $force = false ) {
		$api_key    = get_option('AZURE_AD_CONSUMER_KEY');
		$api_secret = get_option('AZURE_AD_CONSUMER_SECRET');
		$token      = get_option('AZURE_AD_BEARER_TOKEN');

		if ( $api_key && $api_secret && ( ! $token || $force ) ) {

			$provider = new TheNetworg\OAuth2\Client\Provider\Azure(
				[
					'clientId'     => $api_key,
					'clientSecret' => $api_secret,
					'redirectUri'  => plugins_url('', __FILE__),
				]
			);

			$bearer_token_credential = $api_key . ':' . $api_secret;
			$credentials             = base64_encode($bearer_token_credential);

			$args = [
				'method'      => 'POST',
				'httpversion' => '1.1',
				'blocking'    => true,
				'headers'     => [
					'Authorization' => 'Basic ' . $credentials,
					'Content-Type'  => 'application/x-www-form-urlencoded;charset=UTF-8',
				],
				'body'        => [ 'grant_type' => 'client_credentials' ],
			];

			add_filter('https_ssl_verify', '__return_false');
			$response = wp_remote_post('https://api.twitter.com/oauth2/token', $args);

			$keys = json_decode($response['body']);

			if ( $keys ) {
				update_option('AZURE_AD_BEARER_TOKEN', $keys->{'access_token'});
			}
		}
	}


	public function admin_page() {
		if ( ! current_user_can('manage_options') ) {
			wp_die(__('You do not have sufficient permissions to access this page.'));
		}

		if ( $_SERVER['REQUEST_METHOD'] == 'POST' ) {
			update_option('AZURE_AD_CONSUMER_KEY', $_POST['consumer_key']);
			update_option('AZURE_AD_CONSUMER_SECRET', $_POST['consumer_secret']);
			$this->azure_authenticate(true);
		}
		?>
		<div class="afd-admin-options">
			<h1>Azure Front Door</h1>
			<form name="options" method="POST" action="<?php echo $_SERVER['REQUEST_URI']; ?>">
				<label for="consumer_key">Consumer Key<span class="required">(*)</span>: </label>
				<input type="text" name="consumer_key" value="<?php echo get_option('AZURE_AD_CONSUMER_KEY', ''); ?>" size="70">
				<br />
				<label for="consumer_secret">Consumer Secret<span class="required">(*)</span>: </label>
				<input type="text" name="consumer_secret" value="<?php echo get_option('AZURE_AD_CONSUMER_SECRET', ''); ?>" size="70">
				<br />
				<label for="bearer_token">Bearer Token: </label>
				<input type="text" disabled value="<?php echo get_option('AZURE_AD_BEARER_TOKEN', ''); ?>" size="70">
				<br />
				<input class="button-primary" type="submit" name="save" />
				<br/>
				<p>
					You can sign up for a API key <a href="https://dev.afd.com/" target="_blank">here</a><br>
					Your redirect url is: <?php echo plugins_url('', __FILE__); ?>
				</p>
			</form>
			<br />
		</div>
		<?php
	}

}

$purge = new Purge();
