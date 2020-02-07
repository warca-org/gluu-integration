<?php

return array(
    'id' =>             'auth:gluu', # notrans
    'version' =>        '0.1',
    'name' =>           /* trans */ 'Gluu OpenID Connect authentication',
    'author' =>         'WWPass Corporation',
    'description' =>    /* trans */ 'Provides a configurable authentication backend
        for authenticating staff and clients using an Gluu OpenID Connect.',
    'url' =>            'https://github.com/warca-org/gluu-integration',
    'plugin' =>         'authentication.php:OauthAuthPlugin',
    'requires' => array(
        "ohmy/auth" => array(
            "version" => "*",
            "map" => array(
                "ohmy/auth/src" => 'lib',
            )
        ),
    ),
);

?>
