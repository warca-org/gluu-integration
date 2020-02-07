<?php

require_once(INCLUDE_DIR.'class.plugin.php');
require_once('config.php');

class OauthAuthPlugin extends Plugin {
    var $config_class = "OauthPluginConfig";

    function bootstrap() {
        $config = $this->getConfig();

        # ----- Warca ---------------------
        $gluu = $config->get('g-enabled');
        if (in_array($gluu, array('all', 'staff'))) {
            require_once('gluu.php');
            StaffAuthenticationBackend::register(
                new GluuStaffAuthBackend($this->getConfig()));
        }
        if (in_array($gluu, array('all', 'client'))) {
            require_once('gluu.php');
            UserAuthenticationBackend::register(
                new GluuClientAuthBackend($this->getConfig()));
        }
    }
}

require_once(INCLUDE_DIR.'UniversalClassLoader.php');
use Symfony\Component\ClassLoader\UniversalClassLoader_osTicket;
$loader = new UniversalClassLoader_osTicket();
$loader->registerNamespaceFallbacks(array(
    dirname(__file__).'/lib'));
$loader->register();
