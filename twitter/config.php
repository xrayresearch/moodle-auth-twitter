<?php

/**
 * Date: Aug 28, 2013
 * programmer: Shani Mahadeva <satyashani@gmail.com>
 * Description:
 * */

if (!isset ($config->appid)) {
	$config->appid = '';
}
if (!isset ($config->appsecret)) {
	$config->appsecret = '';
}
if (!isset ($config->createuser)) {
	$config->createuser = false;
}
if (!isset ($config->syncuserinfo)) {
	$config->syncuserinfo = true;
}
if (!isset ($config->requireemail)) {
	$config->requireemail = false;
}
?>
<table cellspacing="0" cellpadding="5" border="0">
<tr>
    <td colspan="2">
        <h4><?php print_string('auth_twitter_server_settings', 'auth_twitter') ?></h4>
    </td>
</tr>
<tr valign="top" class="required">
    <td align="right"><label for="appid"><?php print_string('auth_twitter_appid', 'auth_twitter') ?>: </label></td>
    <td>
        <input name="appid" id="appid" type="text" size="30" value="<?php echo $config->appid ?>" />
        <?php if (isset($err['appid'])) { echo $OUTPUT->error_text($err['appid']); } ?>
    </td>
</tr>
<tr valign="top" class="required">
    <td align="right">
        <label for="appsecret"><?php print_string('auth_twitter_appsecret', 'auth_twitter') ?>: </label>
    </td>
    <td>
        <input name="appsecret" id="appsecret" type="text" size="30" value="<?php echo $config->appsecret ?>" />
        <?php if (isset($err['appsecret'])) { echo $OUTPUT->error_text($err['appsecret']); } ?>
    </td>
</tr>
<tr valign="top" class="required">
    <td align="right">
        <?php echo html_writer::label(get_string('auth_twitter_createuser', 'auth_twitter'), 'menucreateuser'); ?>:
    </td>
    <td>
        <input name="createuser" id="createuser" type="checkbox" size="30" <?php echo $config->createuser?"checked":""; ?> />
    </td>
</tr>
<tr valign="top" class="required">
    <td align="right">
        <?php echo html_writer::label(get_string('auth_twitter_syncuserinfo', 'auth_twitter'), 'menusyncuserinfo'); ?>:
    </td>
    <td>
        <input name="syncuserinfo" id="syncuserinfo" type="checkbox" size="30" <?php echo $config->syncuserinfo?"checked":""; ?> />
    </td>
</tr>
<tr valign="top" class="required">
    <td align="right">
        <?php echo html_writer::label(get_string('auth_twitter_requireemail', 'auth_twitter'), 'menurequireemail'); ?>:
    </td>
    <td>
        <input name="requireemail" id="requireemail" type="checkbox" size="30" <?php echo $config->requireemail?"checked":""; ?> />
    </td>
</tr>
</table>
