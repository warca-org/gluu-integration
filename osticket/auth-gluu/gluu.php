<?php
/*
TODO:
 * Create Staff on login if needed
 * Fill profile for Client on login
 * Update profiles on login
 * Make Gluu URL configurable
 * Remove password auth
 * Remove user creation
 */
use ohmy\Auth2;

class GluuAuth {
    var $config;
    var $access_token;

    function __construct($config) {
        $this->config = $config;
    }

    function triggerAuth() {
        $self = $this;
        return Auth2::legs(3)
            ->set('id', $this->config->get('g-client-id'))
            ->set('secret', $this->config->get('g-client-secret'))
            ->set('redirect', 'https://' . $_SERVER['HTTP_HOST']
                . ROOT_PATH . 'api/auth/ext')
            ->set('scope', 'profile email')

            ->authorize('https://iam.warca.net/oxauth/restv1/authorize')
            ->access('https://iam.warca.net/oxauth/restv1/token')

            ->finally(function($data) use ($self) {
                $self->access_token = $data['access_token'];
            });
    }
}

class GluuStaffAuthBackend extends ExternalStaffAuthenticationBackend {
    static $id = "warca";
    static $name = "Warca";

    static $sign_in_image_url = "https://www.warca.org/wp-content/uploads/2020/02/logo.png";
    static $service_name = "Warca";

    var $config;

    function __construct($config) {
        $this->config = $config;
        $this->warca = new GluuAuth($config);
    }

    function signOn() {
        // TODO: Check session for auth token
        if (isset($_SESSION[':oauth']['email'])) {
            if (($staff = StaffSession::lookup(array('email' => $_SESSION[':oauth']['email'])))
                && $staff->getId()
            ) {
                if (!$staff instanceof StaffSession) {
                    // osTicket <= v1.9.7 or so
                    $staff = new StaffSession($user->getId());
                }
                return $staff;
            }
            else
                $_SESSION['_staff']['auth']['msg'] = 'Have your administrator create a local account';
        }
    }

    static function signOut($user) {
        parent::signOut($user);
        unset($_SESSION[':oauth']);
    }


    function triggerAuth() {
        parent::triggerAuth();
        $warca = $this->warca->triggerAuth();
        $warca->GET(
            "https://iam.warca.net/oxauth/restv1/userinfo?access_token="
                . $this->warca->access_token)
            ->then(function($response) {
                require_once INCLUDE_DIR . 'class.json.php';
                if ($json = JsonDataParser::decode($response->text))
                    $_SESSION[':oauth']['email'] = $json['email'];
                Http::redirect(ROOT_PATH . 'scp');
            }
        );
    }
}

class GluuClientAuthBackend extends ExternalUserAuthenticationBackend {
    static $id = "warca.client";
    static $name = "Warca";

    static $sign_in_image_url = "https://www.warca.org/wp-content/uploads/2020/02/logo.png";
    static $service_name = "Warca";

    function __construct($config) {
        $this->config = $config;
        $this->warca = new GluuAuth($config);
    }

    function supportsInteractiveAuthentication() {
        return false;
    }

    function signOn() {
        // TODO: Check session for auth token
        if (isset($_SESSION[':oauth']['email'])) {
            if (($acct = ClientAccount::lookupByUsername($_SESSION[':oauth']['email']))
                    && $acct->getId()
                    && ($client = new ClientSession(new EndUser($acct->getUser()))))
                return $client;

            elseif (isset($_SESSION[':oauth']['profile'])) {
                // TODO: Prepare ClientCreateRequest
                $profile = $_SESSION[':oauth']['profile'];
                $info = array(
                    'email' => $_SESSION[':oauth']['email'],
                    'name' => $profile['displayName'],
                );
                return new ClientCreateRequest($this, $info['email'], $info);
            }
        }
    }

    static function signOut($user) {
        parent::signOut($user);
        $location = 'https://iam.warca.net/oxauth/restv1/end_session?'.http_build_query(array(
            'id_token_hint' => $_SESSION[':oauth']['access_token']
        ));
        header("Location: $location");
        unset($_SESSION[':oauth']);
        exit();
    }

    function triggerAuth() {
        require_once INCLUDE_DIR . 'class.json.php';
        parent::triggerAuth();
        $warca = $this->warca->triggerAuth();
        $token = $this->warca->access_token;
        $warca->GET(
            "https://iam.warca.net/oxauth/restv1/userinfo?access_token="
                . $token)
            ->then(function($response) use ($warca, $token) {
                if (!($json = JsonDataParser::decode($response->text)))
                    return;
                $_SESSION[':oauth']['email'] = $json['email'];
                $_SESSION[':oauth']['profile'] = $json;
                $_SESSION[':oauth']['access_token'] = $token;
                Http::redirect(ROOT_PATH . 'login.php');
            }
        );
    }
}


