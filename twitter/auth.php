<?php

/**
 * @author Martin Dougiamas
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package moodle multiauth
 *
 * Authentication Plugin: No Authentication
 *
 * No authentication at all. This method approves everything!
 *
 * 2006-08-31  File created.
 */

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');    ///  It must be included from a Moodle page
}

require_once($CFG->libdir.'/authlib.php');
require_once($CFG->dirroot.'/auth/twitter/twitteroauth/twitteroauth.php');
/**
 * Plugin for no authentication.
 */
class auth_plugin_twitter extends auth_plugin_base {

	private $twO;
	/**
     * Constructor.
     */
    function auth_plugin_twitter() {
		global $CFG;
        $this->authtype = 'twitter';
        $this->config = get_config('auth/twitter');
		if(!isset($this->config->appid)){
			$plugin = 'auth/twitter';
			set_config('appid', "", $plugin);
			set_config('appsecret', "", $plugin);
			set_config('createuser', 0, $plugin);
			set_config('syncuserinfo', 1, $plugin);
			set_config('requireemail', 1, $plugin);
			set_config('callback', $CFG->wwwroot."/login/index.php", $plugin);
			$this->config = get_config("auth/twitter");
		}
		$this->twO = new TwitterOAuth($this->config->appid,$this->config->appsecret);
    }
	
	function getTwitterLoginUrl(){
		if(session_id()=='') {
			session_start();
		}
		if(!isset($_SESSION['oauth_token'])){
			$request_token = $this->twO->getRequestToken($this->config->callback);
			$_SESSION['oauth_token'] = $request_token['oauth_token'];
			$_SESSION['oauth_token_secret'] = $request_token['oauth_token_secret'];
		}
		$token = $_SESSION['oauth_token'];
		return $this->twO->getAuthorizeURL($token); 
	}

    /**
     * Returns true if the username and password work or don't exist and false
     * if the user exists and the password is wrong.
     *
     * @param string $username The username
     * @param string $password The password
     * @return bool Authentication success or failure.
     */
    function user_login ($username, $password) {
		return isset($_SESSION['access_token'])&&!empty($_SESSION['access_token']);
    }
	
	function get_userinfo($username) {
		$access_token = $_SESSION['access_token'];
		$connectionNew = new TwitterOAuth($this->config->appid,$this->config->appsecret, $access_token['oauth_token'],$access_token['oauth_token_secret']);
		$account = $connectionNew->get('users/lookup');
		return $account;
	}

	
	/**
     * Updates the user's password.
     *
     * called when the user password is updated.
     *
     * @param  object  $user        User table object
     * @param  string  $newpassword Plaintext password
     * @return boolean result
     *
     */
    function user_update_password($user, $newpassword) {
        $user = get_complete_user_data('id', $user->id);
        return update_internal_user_password($user, $newpassword);
    }

    function prevent_local_passwords() {
        return false;
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return true;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    function can_change_password() {
        return true;
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    function change_password_url() {
        return null;
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    function can_reset_password() {
        return true;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $page An object containing all the data for this page.
     */
    function config_form($config, $err, $user_fields) {
        include "config.php";
		
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     */
    function process_config($config) {
        global $CFG;
		if (!isset ($config->appid)) {
			$config->appid = '';
		}
		if (!isset ($config->appsecret)) {
			$config->appsecret = '';
		}
		if (!isset ($config->createuser)) {
			$config->createuser = 0;
		}else{
			$config->createuser = 1;
		}
		if (!isset ($config->syncuserinfo)) {
			$config->syncuserinfo = 0;
		}else{
			$config->syncuserinfo = 1;
		}
		if (!isset ($config->requireemail)) {
			$config->requireemail = 0;
		}else{
			$config->requireemail = 1;
		}
		$plugin = 'auth/twitter';
        set_config('appid', trim($config->appid), $plugin);
        set_config('appsecret', trim($config->appsecret), $plugin);
        set_config('createuser', $config->createuser, $plugin);
        set_config('syncuserinfo', trim($config->syncuserinfo), $plugin);
		set_config('requireemail', trim($config->requireemail), $plugin);
		set_config('callback', $CFG->wwwroot."/login/index.php", $plugin);
		return true;
    }
	
	function loginpage_hook() {
		global $CFG, $frm,$user;
		$frm = data_submitted();
		if(!$frm) $frm = new stdClass ();
		if(!isset($_REQUEST['oauth_token'])&&!isset($frm->username))
			include($CFG->dirroot."/auth/twitter/twitterlogin.php");
		if(isset($_SESSION['oauth_token'])&&isset($_REQUEST['oauth_token']) && $_SESSION['oauth_token'] == $_REQUEST['oauth_token']){
			/* Create TwitteroAuth object with app key/secret and token key/secret from default phase */
			$connection = new TwitterOAuth($this->config->appid, $this->config->appsecret, $_SESSION['oauth_token'], $_SESSION['oauth_token_secret']);
			/* Request access tokens from twitter */
			$access_token = $connection->getAccessToken($_REQUEST['oauth_verifier']);
			/* Save the access tokens. Normally these would be saved in a database for future use. */
			$_SESSION['access_token'] = $access_token;
			/* Remove no longer needed request tokens */
			unset($_SESSION['oauth_token']);
			unset($_SESSION['oauth_token_secret']);

			$connectionNew = new TwitterOAuth($this->config->appid, $this->config->appsecret, $access_token['oauth_token'],$access_token['oauth_token_secret']);
			$account = $connectionNew->get('account/settings');
			$email = "@".$account->screen_name;
			$u = $this->getMoodleUser($email);
			if($u){
				if($u->auth=='twitter'){
					$frm->username = $u->username;
					$frm->password = "Rewq!234";
				}else{
					$user = $u;
				}
			}
			else{
				if($this->config->createuser){
					$extended = $connectionNew->get("users/show",array("screen_name"=>$account->screen_name));
					$name = explode(" ", $extended->name,2);
					$usernew = new stdClass();
					$usernew->username = $email;
					$usernew->password = "Rewq!234";
					if($this->config->requireemail)
						$usernew->email = "";
					else
						$usernew->email = $account->screen_name."@twitter.com";
					$usernew->auth = "twitter";
					$usernew->firstname = $name[0];
					$usernew->lastname  = isset($name[1])?$name[1]:"";
					$usernew->confirmed = 1;
					$usernew->mnethostid = $CFG->mnet_localhost_id;
					if($this->user_signup($usernew)){
						$frm->username = $email;
						$frm->password = "Rewq!234";
					}
				}
			}
		}else{
			if(isset($_REQUEST['oauth_token'])&&!empty($_REQUEST['oauth_token'])){
				unset($_SESSION['oauth_token']);
				unset($_SESSION['oauth_token_secret']);
			}
		}
	}
	
	function user_exists($username){
		global $DB;
		$user = $DB->get_record("user",array("username"=>$username));
		return is_object($user)&&property_exists($user, "id")&&  is_numeric($user->id);
	}
	
	
	function user_signup($user, $notify = false) {
		global $CFG, $DB, $PAGE, $OUTPUT;

        require_once($CFG->dirroot.'/user/profile/lib.php');

        if ($this->user_exists($user->username)) {
            print_error('auth_twitter_user_exists', 'auth_twitter');
        }

        $plainslashedpassword = $user->password;

        $user->id = $DB->insert_record('user', $user);
		profile_save_data($user);
        // This will also update the stored hash to the latest algorithm
        // if the existing hash is using an out-of-date algorithm (or the
        // legacy md5 algorithm).
        update_internal_user_password($user, $plainslashedpassword);

        $user = $DB->get_record('user', array('id'=>$user->id));
        events_trigger('user_created', $user);

        
        if ($notify) {
            $emailconfirm = get_string('emailconfirm');
            $PAGE->set_url('/auth/ldap/auth.php');
            $PAGE->navbar->add($emailconfirm);
            $PAGE->set_title($emailconfirm);
            $PAGE->set_heading($emailconfirm);
            echo $OUTPUT->header();
            notice(get_string('emailconfirmsent', '', $user->email), "{$CFG->wwwroot}/index.php");
        } else {
			return true;
		}
	}



	/**
	 * Retrieve the Moodle user given username of twitter user
	 * 
	 * @param int $fb_id Facebook User ID
	 * @return string Moodle User ID
	 */
	function getMoodleUser($twittername) {
		global $DB;
		return $DB->get_record('user', array('username' => $twittername), '*');
	}
	
	function prelogout_hook(){
		unset($_SESSION['access_token']);
	}
	
}


