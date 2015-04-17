<?php
/**
 * Plugin Name: IFC LDAP Auth
 * Plugin URI: araquari.ifc.edu.br
 * Description: Autenticação de usuários através do LDAP.
 * Version: 0.0.1
 * Author: IFC Araquari
 * Author URI: araquari.ifc.edu.br
 * License: MIT
 */

add_filter('authenticate', 'ldapAuthPlugin', 10, 3);

// Comment this line if you wish to fall back on WordPress authentication
// Useful for times when the external service is offline
remove_action('authenticate', 'wp_authenticate_username_password', 20);

function ldapAuthPlugin($user, $username, $password) {
  if ($username == '' || $password == '') return new WP_Error('denied', __("ERROR: Forneça os dados corretamente"));;
  
  // Se for o usuário admin redireciona para a autenticação padrão do WordPress
  if ($username == 'admin') return wp_authenticate_username_password(null, $username, $password);
  
  $ldap_user = ladpAuthenticate($username, $password);
  
  if ($ldap_user) {
    $wp_user = new WP_User(null, $ldap_user['uid'][0]);
      
    if ($wp_user->exists()) {
      // Atualizar usuário no wp
      $userdata = array(
        'ID'           => $wp_user->ID,
        'user_pass'    => $password,
        'user_email'   => $ldap_user['privatemail'][0],
      );
       
      $user_id = wp_update_user($userdata);
      return new WP_User($user_id);
    } else {
      // Inserir usuário no wp
      $userdata = array(
        'user_login'   => $ldap_user['uid'][0],
        'user_pass'    => $password,
        'user_email'   => $ldap_user['privatemail'][0],
        'display_name' => $ldap_user['cn'][0],
        'first_name'   => $ldap_user['givenname'][0],
        'last_name'    => $ldap_user['sn'][0]
      );
       
      $user_id = wp_insert_user($userdata);
      return new WP_User($user_id);
    }
    
  } else {
    return new WP_Error('denied', __("ERROR: Usuário ou senha inválidos!"));
  }
}

function ldapGetConnection() {
  $options    = get_option('ifc_auth_settings');
  $connection = @ldap_connect($options['ifc_auth_host'], $options['ifc_auth_port']);
  ldap_set_option($connection, LDAP_OPT_PROTOCOL_VERSION, 3);
  ldap_set_option($connection, LDAP_OPT_REFERRALS, 0);
  
  return $connection;
}

function ladpAuthenticate($username, $password) {
  $options    = get_option('ifc_auth_settings');
  $conn       = ldapGetConnection();
  $base_dn    = $options['ifc_auth_base_dn'];
  $service_dn = $options['ifc_auth_service_dn'];
  $filter     = "(&(uid=$username)(active=TRUE)(memberOf=$service_dn))";
  
  $result     = @ldap_search($conn, $base_dn, $filter);
  $entries    = @ldap_get_entries($conn, $result);
  
  if ($entries['count'] != 0) {
    $user = $entries[0];
    $ldap_bind = @ldap_bind($conn, $user['dn'], $password);

    if ($ldap_bind) {
      // Usuário autenticado com sucesso
      return $user;
    } else {
      // Senha inválida
      return false;
    }
    
  } else {
    // Usuário não encontrado
    return false;
  }
}

// Option page
add_action('admin_menu', 'ifc_auth_add_admin_menu');
add_action('admin_init', 'ifc_auth_settings_init');

function ifc_auth_add_admin_menu() { 
	add_options_page('IFC LDAP Auth', 'IFC LDAP Auth', 'manage_options', 'ifc_auth', 'ifc_auth_options_page');
}

function ifc_auth_settings_init() {
	register_setting( 'pluginPage', 'ifc_auth_settings' );

	add_settings_section(
		'ifc_auth_section', 
		"Configurações do diretório", 
		null, 
		'pluginPage'
	);

	add_settings_field( 
		'ifc_auth_host_field', 
		'Host', 
		'ifc_auth_host_field_render', 
		'pluginPage', 
		'ifc_auth_section' 
	);

	add_settings_field( 
		'ifc_auth_port_field', 
		'Port', 
		'ifc_auth_port_field_render', 
		'pluginPage', 
		'ifc_auth_section' 
	);

	add_settings_field( 
		'ifc_auth_base_bn_field', 
		'Base DN', 
		'ifc_auth_base_dn_field_render', 
		'pluginPage', 
		'ifc_auth_section' 
	);

	add_settings_field( 
		'ifc_auth_service_dn_field', 
		'Service DN', 
		'ifc_auth_service_dn_field_render', 
		'pluginPage', 
		'ifc_auth_section' 
	);
}

function ifc_auth_host_field_render() { 
	$options = get_option( 'ifc_auth_settings' );  
	?>
    <input type='text' name='ifc_auth_settings[ifc_auth_host]' value='<?php echo $options['ifc_auth_host']; ?>' size="30">
	<?php
}


function ifc_auth_port_field_render() { 
	$options = get_option( 'ifc_auth_settings' );
	?>
    <input type='text' name='ifc_auth_settings[ifc_auth_port]' value='<?php echo $options['ifc_auth_port']; ?>' size="6">
	<?php
}


function ifc_auth_base_dn_field_render() { 
	$options = get_option( 'ifc_auth_settings' );
	?>
    <input type='text' name='ifc_auth_settings[ifc_auth_base_dn]' value='<?php echo $options['ifc_auth_base_dn']; ?>' size="60">
	<?php
}


function ifc_auth_service_dn_field_render() { 
	$options = get_option( 'ifc_auth_settings' );
	?>
    <input type='text' name='ifc_auth_settings[ifc_auth_service_dn]' value='<?php echo $options['ifc_auth_service_dn']; ?>' size="60">
	<?php
}


function ifc_auth_settings_section_callback() { 
	echo '';
}


function ifc_auth_options_page() { 
	?>
    <form action='options.php' method='post'>
      
      <h2>IFC Auth</h2>
      
      <?php
        settings_fields( 'pluginPage' );
        do_settings_sections( 'pluginPage' );
        submit_button();
      ?>
      
    </form>
	<?php
}