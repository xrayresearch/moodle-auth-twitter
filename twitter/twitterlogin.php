<?php

/**
 * Date: Aug 24, 2013
 * programmer: Shani Mahadeva <satyashani@gmail.com>
 * Description:
 * */
global $CFG;
$auth = new auth_plugin_twitter();
$url = $auth->getTwitterLoginUrl();
$imgsignin = $CFG->wwwroot."/auth/twitter/images/lighter.png";
?>
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
<a class='twitter-login-button' id="twitterlogin" href="<?php echo $url;?>" style="display: none;margin: 0px 10px; top:8px;">
	<img src="<?php echo $imgsignin;?>" />
</a>
<script>
	$(document).ready(function(){
		$("input#loginbtn").after($("a#twitterlogin"));
		$("a#twitterlogin").show();
	})
</script>
</body>
</html>