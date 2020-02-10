<?php
/*
TODO:
 * Make Gluu URL configurable
 * Make login button configurable
 * Remove password auth
 * Remove user registration
 * Find users by inum, not by email
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
        $this->gluu = new GluuAuth($config);
    }

    function signOn() {
        global $cfg;
        if (isset($_SESSION[':oauth']['email']) && isset($_SESSION[':oauth']['access_token'])) {
            if (
                !isset($_SESSION[':oauth']['profile']['member_of']) ||
                !in_array('inum=' . $this->config->get('g-staff-inum') . ',ou=groups,o=gluu',$_SESSION[':oauth']['profile']['member_of'])) {
                    $_SESSION['_staff']['auth']['msg'] = __('Access denied');
                    return new AccessDenied(__('Access denied'));
            }
            $staff_profile_update = array();
            if (($staff = StaffSession::lookup(array('email' => $_SESSION[':oauth']['email'])))
                && $staff->getId()
            ) {
                $staff_profile_update['id'] = $staff->getId();
            } else {
                $staff = Staff::create();
            }
            $gluu_profile = $_SESSION[':oauth']['profile'];
            $names = explode(' ',$gluu_profile['name'],2); // TODO: Use PersonsName
            $staff_profile_update = array_merge($staff_profile_update, array(
                'email' => $gluu_profile['email'],
                'username' => str_replace('@','_at_',$gluu_profile['email']),
                'firstname' => $names[0],
                'lastname' => isset($names[1])?$names[1]:$names[0],
                'dept_id' => $cfg->getDefaultDeptId(),
                'role_id' => $this->config->get('g-staff-initial-role'),
                'backend' => self::$id,
                'isadmin' => isset($gluu_profile['member_of']) && in_array('inum=' . $this->config->get('g-admin-inum') . ',ou=groups,o=gluu', $gluu_profile['member_of'])
            ));
            if (!$staff->update($staff_profile_update,$errors)) {
                if(!$errors['err']) {
                    $errors['err'] = sprintf('%s %s',
                        sprintf(__('Unable to add %s.'), __('this agent')),
                        __('Correct any errors below and try again.'));
                }
                return new AccessDenied(__('Access denied'));
            }
            if (!$staff instanceof StaffSession) {
                $staff = new StaffSession($user->getId());
            }
            return $staff;

    }
        unset($_SESSION[':oauth']);
    }

    static function signOut($user) {
        parent::signOut($user);
        $location = 'https://iam.warca.net/oxauth/restv1/end_session?'.http_build_query(array(
//            'id_token_hint' => $_SESSION[':oauth']['access_token'],
            'post_logout_redirect_uri' => 'https://' . $_SERVER['HTTP_HOST'] . ROOT_PATH . 'scp/'
        ));
        header("Location: $location");
        unset($_SESSION[':oauth']);
        exit();
    }


    function triggerAuth() {
        parent::triggerAuth();
        $gluu = $this->gluu->triggerAuth();
        $token = $this->gluu->access_token;
        $gluu->GET(
            "https://iam.warca.net/oxauth/restv1/userinfo?access_token="
                . urlencode($token))
            ->then(function($response) use ($token) {
                require_once INCLUDE_DIR . 'class.json.php';
                if ($json = JsonDataParser::decode($response->text)) {
                    $_SESSION[':oauth']['email'] = $json['email'];
                    $_SESSION[':oauth']['profile'] = $json;
                    $_SESSION[':oauth']['access_token'] = $token;
                }
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
        $this->gluu = new GluuAuth($config);
    }

    function supportsInteractiveAuthentication() {
        return false;
    }

    function signOn() {

        if (isset($_SESSION[':oauth']['email']) && isset($_SESSION[':oauth']['access_token']) && isset($_SESSION[':oauth']['profile'])) {
            $profile = $_SESSION[':oauth']['profile'];
            if (($acct = ClientAccount::lookupByUsername($_SESSION[':oauth']['email']))
                    && $acct->getId()) {
                $user = $acct->getUser();
                $user->name = $profile['name'];
                if (!$user->save()) {
                    return new AccessDenied(__('Internal error. Cannot update Name field'));
                }
                $client = new ClientSession(new EndUser($user));
                return $client;
            } else {
                $info = array(
                    'email' => $_SESSION[':oauth']['email'],
                    'name' => $profile['name'],
                );
                return new ClientCreateRequest($this, $info['email'], $info);
            }
        }
    }

    static function signOut($user) {
        parent::signOut($user);
        $location = 'https://iam.warca.net/oxauth/restv1/end_session?'.http_build_query(array(
//            'id_token_hint' => $_SESSION[':oauth']['access_token'],
            'post_logout_redirect_uri' => 'https://' . $_SERVER['HTTP_HOST'] . ROOT_PATH
        ));
        header("Location: $location");
        unset($_SESSION[':oauth']);
        exit();
    }

    function triggerAuth() {
        require_once INCLUDE_DIR . 'class.json.php';
        parent::triggerAuth();
        $gluu = $this->gluu->triggerAuth();
        $token = $this->gluu->access_token;
        $gluu->GET(
            "https://iam.warca.net/oxauth/restv1/userinfo?access_token="
                . urlencode($token))
            ->then(function($response) use ($token) {
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


