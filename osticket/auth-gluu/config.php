<?php

require_once INCLUDE_DIR . 'class.plugin.php';

class OauthPluginConfig extends PluginConfig {

    // Provide compatibility function for versions of osTicket prior to
    // translation support (v1.9.4)
    function translate() {
        if (!method_exists('Plugin', 'translate')) {
            return array(
                function($x) { return $x; },
                function($x, $y, $n) { return $n != 1 ? $y : $x; },
            );
        }
        return Plugin::translate('auth-oauth');
    }

    function getOptions() {
        list($__, $_N) = self::translate();
        $modes = new ChoiceField(array(
            'label' => $__('Authentication'),
            'choices' => array(
                '0' => $__('Disabled'),
                'staff' => $__('Agents Only'),
                'client' => $__('Clients Only'),
                'all' => $__('Agents and Clients'),
            ),
        ));
        return array(
            'warca' => new SectionBreakField(array(
                'label' => $__('Warca Authentication'),
            )),
            'g-client-id' => new TextboxField(array(
                'label' => $__('Client ID'),
                'configuration' => array('size'=>60, 'length'=>100),
            )),
            'g-client-secret' => new TextboxField(array(
                'label' => $__('Client Secret'),
                'configuration' => array('size'=>60, 'length'=>100),
            )),
            'g-staff-inum' => new TextboxField(array(
                'label' => $__('Inum of staff group'),
                'configuration' => array('size'=>60, 'length'=>100),
            )),
            'g-admin-inum'  => new TextboxField(array(
                'label' => $__('Inum of admin group'),
                'configuration' => array('size'=>60, 'length'=>100),
            )),
            'g-staff-initial-role' => new ChoiceField(array(
                'label' => $__('Initial role for new staff accounts'),
                'choices'=> Role::getActiveRoles(),
            )),
            'g-enabled' => clone $modes,
        );
    }
}
